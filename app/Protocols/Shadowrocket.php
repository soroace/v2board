<?php

namespace App\Protocols;

use App\Utils\Helper;

class Shadowrocket
{
    public $flag = 'shadowrocket';
    private $servers;
    private $user;

    public function __construct($user, $servers)
    {
        $this->user = $user;
        $this->servers = $servers;
    }

    public function handle()
    {
        $user = $this->user;

        // 本站凭据只取一次：外部节点的 _credential 只写局部变量，
        // 不能写 $user['uuid'] —— $this->user 是共享的 Eloquent 模型
        $defaultUuid = $this->user['uuid'];

        $uri = '';
        //display remaining traffic and expire date
        $upload = round($user['u'] / (1024*1024*1024), 2);
        $download = round($user['d'] / (1024*1024*1024), 2);
        $totalTraffic = round($user['transfer_enable'] / (1024*1024*1024), 2);
        $expiredDate = $user['expired_at'] === NULL ? '长期有效' : date('Y-m-d', $user['expired_at']);
        $uri .= "STATUS=🚀↑:{$upload}GB,↓:{$download}GB,TOT:{$totalTraffic}GB💡Expires:{$expiredDate}\r\n";

        foreach ($this->servers as $server) {
            // 外部订阅节点使用其自身凭据；只写局部变量，不要写 $user['uuid']（那是共享的 Eloquent 模型）
            $uuid = isset($server['_credential']) && $server['_credential'] !== '' ? $server['_credential'] : $defaultUuid;
            if ($server['type'] === 'vmess' || ($server['type'] === 'v2node' && $server['protocol'] === 'vmess')) {
                // Shadowrocket 的 vmess URI 只表达 tcp / ws / grpc；vless / trojan 走 Helper::buildUri（已知传输都忠实）
                if (!Helper::networkExpressible('shadowrocket', 'vmess', $server['network'] ?? null)) continue;
                $uri .= self::buildVmess($uuid, $server);
            } else {
                $uri .= Helper::buildUri($uuid, $server);
            }
        }
        return base64_encode($uri);
    }

    public static function buildVmess($uuid, $server)
    {
        $userinfo = base64_encode('auto:' . $uuid . '@' . $server['host'] . ':' . $server['port']);
        $config = [
            'tfo' => 1,
            'remark' => $server['name'],
            'alterId' => 0
        ];
        if ($server['tls']) {
            $config['tls'] = 1;
            $tlsSettings = $server['tls_settings'] ?? ($server['tlsSettings'] ?? []);
            $config['allowInsecure'] = (int)($tlsSettings['allow_insecure'] ?? $tlsSettings['allowInsecure'] ?? 0);
            $config['peer'] = $tlsSettings['server_name'] ?? $tlsSettings['serverName'] ?? '';
        }
        if ($server['network'] === 'tcp') {
            $tcpSettings = $server['network_settings'] ?? ($server['networkSettings'] ?? []);
            if (isset($tcpSettings['header']['type']) && !empty($tcpSettings['header']['type']))
                $config['obfs'] = $tcpSettings['header']['type'];
            if (isset($tcpSettings['header']['request']['path'][0]) && !empty($tcpSettings['header']['request']['path'][0]))
                $config['path'] = $tcpSettings['header']['request']['path'][0];
            if (isset($tcpSettings['header']['request']['headers']['Host'][0]))
                $config['obfsParam'] = $tcpSettings['header']['request']['headers']['Host'][0];
        }
        if ($server['network'] === 'ws') {
            $config['obfs'] = "websocket";
            $wsSettings = $server['network_settings'] ?? ($server['networkSettings'] ?? []);
            if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                $config['path'] = $wsSettings['path'];
            if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                $config['obfsParam'] = $wsSettings['headers']['Host'];
            if (isset($wsSettings['security']))
                $config['method'] = $wsSettings['security'];
        }
        if ($server['network'] === 'grpc') {
            $config['obfs'] = "grpc";
            $grpcSettings = $server['network_settings'] ?? ($server['networkSettings'] ?? []);
            if (isset($grpcSettings['serviceName']) && !empty($grpcSettings['serviceName']))
                $config['path'] = $grpcSettings['serviceName'];
            if (isset($tlsSettings)) {
                $config['host'] = $tlsSettings['server_name'] ?? $tlsSettings['serverName'] ?? '';
            } else {
                $config['host'] = $server['host'];
            }
        }
        $query = http_build_query($config, '', '&', PHP_QUERY_RFC3986);
        $uri = "vmess://{$userinfo}?{$query}";
        $uri .= "\r\n";
        return $uri;
    }

}

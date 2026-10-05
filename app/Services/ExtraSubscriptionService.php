<?php

namespace App\Services;

use App\Utils\Helper;
use App\Utils\SubscriptionParser;
use GuzzleHttp\Client;
use Illuminate\Support\Facades\Log;

/**
 * 额外订阅（附加节点）服务：拉取与下发分离 —— refresh() 由定时任务（extra:subscribe，每分钟）
 * 拉取并落盘；merge() 在用户订阅请求里只读本地文件，绝不发 HTTP。
 * 存储 storage/app/extra-subscribe.json（临时文件 + rename 原子替换），每条链接一份；
 * 拉取失败只写 error / last_attempt_at，不动 nodes（旧节点继续下发）。
 * 安全：文件含第三方凭据，日志里链接一律打码；链接只来自后台配置（仅管理员可改），
 * 与自定义订阅 URL 同一信任模型，故不做内网 SSRF 检查，只留 http/https 白名单。
 */
class ExtraSubscriptionService
{
    /** 落盘文件名（storage/app 下） */
    const STORE_FILE = 'extra-subscribe.json';

    /** 响应体大小上限（字节） */
    const MAX_BODY_BYTES = 2097152; // 2MB

    /** 刷新间隔下限（秒）：后台设得再小也会被抬到这里 */
    const MIN_REFRESH_TTL = 30;

    /** 刷新间隔上限（秒）：后台设得再大也会被压到这里 */
    const MAX_REFRESH_TTL = 86400; // 1 天

    /** 拉取失败后的重试间隔（秒） */
    const FAIL_RETRY_TTL = 60;

    /** 上一次成功的结果最长沿用（秒） */
    const MAX_STALE_TTL = 604800; // 7 天

    /** 链接条数上限（超出只取前几条并记 warning） */
    const MAX_URLS = 10;

    /** 后台「缓存时间」缺省值（秒）。键名是历史遗留，语义就是「多久去第三方刷新一次」 */
    const DEFAULT_REFRESH_TTL = 3600; // 1 小时

    /** 请求超时缺省值（秒） */
    const DEFAULT_TIMEOUT = 15;

    /** 请求超时下限（秒）：后台设得再小也会被抬到这里 */
    const MIN_TIMEOUT = 3;

    /** 请求超时上限（秒）：后台设得再大也会被压到这里 */
    const MAX_TIMEOUT = 30;

    /**
     * 每种协议必须齐备的键。渲染器对其中多数是无守护读取，缺键 → 整份订阅 500，
     * 所以脏存储里的节点不能只看 type/host/port。表按 SubscriptionParser 的实际输出整理
     * （snake_case 与 camelCase 两套都有渲染器在读），tools/type-fields-audit.php 守着不漂移。
     */
    private static $nodeFields = array(
        'shadowsocks' => array('cipher'),
        'vmess'       => array('tls', 'tls_settings', 'tlsSettings', 'network', 'network_settings', 'networkSettings'),
        'vless'       => array('tls', 'tls_settings', 'tlsSettings', 'encryption', 'flow',
                               'network', 'network_settings', 'networkSettings'),
        'trojan'      => array('tls', 'tls_settings', 'tlsSettings', 'server_name', 'allow_insecure',
                               'network', 'network_settings', 'networkSettings'),
        'hysteria'    => array('version', 'insecure', 'up_mbps', 'down_mbps', 'server_name',
                               'tls_settings', 'tlsSettings'),
        'tuic'        => array('disable_sni', 'zero_rtt_handshake', 'congestion_control', 'udp_relay_mode',
                               'insecure', 'server_name', 'tls_settings', 'tlsSettings'),
        'anytls'      => array('tls', 'tls_settings', 'tlsSettings', 'insecure', 'server_name',
                               'network', 'network_settings', 'networkSettings'),
    );

    /**
     * 这些键只要存在就必须是数组：$nodeFields 只查「键在不在」，拦不住「键在但值不是数组」。
     * 渲染器会 `$x = $server['tls_settings'] ?? []` 再直接下标，PHP 8 下对字符串下标取值是
     * TypeError（不是 warning，catch 不到）→ 整份订阅 500。只可能来自手改 / 残留存储，
     * 解析器产出这几个键时一律是数组。
     */
    private static $nodeArrayKeys = array('tls_settings', 'tlsSettings', 'network_settings', 'networkSettings');

    /**
     * 第二层：这些字段的取值也必须合法（只收会让渲染器抛异常或客户端拒收的）。
     * - ss cipher：白名单即 Helper::SS_CIPHERS；ClashMeta / ClashVerge / Stash / Singbox 没有
     *   自己的白名单，会把空值或陌生值原样写进配置；2022-blake3-* 更不能放 —— 它的 server key
     *   要靠 created_at 派生，外部节点没有 → ss2022 分支整份订阅 500
     * - vless encryption：只放行 'none'；非 none 需要 URI 里没有的 4 个设置，放行要么 500、
     *   要么出一个必然连不上的僵尸节点
     * network / port 不进这张表（前者有 networkExpressible 逐格判定，后者多端口形态合法）。
     */
    private static $nodeValues = array(
        'shadowsocks' => array(
            'cipher' => Helper::SS_CIPHERS,
        ),
        // 走到这里时 encryption 必定存在（上面 $nodeFields['vless'] 已保证键齐）
        'vless' => array(
            'encryption' => array('none'),
        ),
    );

    /**
     * 把额外订阅的节点合并进本站节点列表（用户请求路径：只读本地，不发 HTTP）
     */
    public function merge(array $servers)
    {
        // 附加订阅不允许影响本站节点下发：整段兜住所有 Throwable（含依赖不兼容的 PHP Error）
        try {
            $nodes = $this->nodes();
            if (!$nodes) {
                return $servers;
            }

            // 已占用名字：本站节点优先
            $used = array();
            foreach ($servers as $server) {
                if (isset($server['name']) && is_scalar($server['name'])) {
                    $used[(string)$server['name']] = true;
                }
            }

            $added = array();
            foreach ($nodes as $node) {
                // 存储可能残留旧格式或被手改：脏节点直接丢弃。type/host/port 是渲染器无守护读取的字段
                // （共 32 处直接读 $server['host']），缺一个就把整份订阅打成 500，所以必须自己筛。
                if (!is_array($node)) {
                    continue;
                }
                $type = isset($node['type']) && is_scalar($node['type']) ? (string)$node['type'] : '';
                $host = isset($node['host']) && is_scalar($node['host']) ? trim((string)$node['host']) : '';
                $port = isset($node['port']) && is_scalar($node['port']) ? (string)$node['port'] : '';
                if ($type === '' || $host === '' || $port === '') {
                    continue;
                }
                // 存储会跨版本存活：可能缺「可选但被渲染器无守护读取」的键，先补齐再校验。
                $node = self::repairOptionalKeys($type, $node);
                // 类型必需字段：脏存储里的节点只看 type/host/port 不够，缺协议字段渲染器就抛异常
                if (!self::nodeComplete($type, $node)) {
                    continue;
                }
                $name = isset($node['name']) && is_scalar($node['name']) ? trim((string)$node['name']) : '';

                if ($name === '') {
                    // URI 没带 #名字：用 host:port 兜底（撞名加序号），别把整条链接的节点丢掉
                    $base = $host . ':' . $port;
                    $name = $base;
                    $seq = 1;
                    while (isset($used[$name])) {
                        $seq++;
                        $name = $base . ' #' . $seq;
                    }
                } elseif (isset($used[$name])) {
                    // 有名字的：重名跳过（本站优先）
                    continue;
                }

                $used[$name] = true;
                $node['name'] = $name;
                $added[] = $node;
            }

            if (!$added) {
                return $servers;
            }

            // 附加节点始终排在后面
            return array_merge($servers, $added);
        } catch (\Throwable $e) {
            // 节点名可能带地址，异常消息一律打码后再落日志
            Log::warning('extra subscribe: merge failed - ' . $this->maskText($e->getMessage()));
            return $servers;
        }
    }

    /**
     * 拉取并落盘（供定时任务 / 手动执行调用）
     *
     * @param  bool $force 忽略刷新间隔，强制全部重拉
     * @return array ['refreshed' => 成功条数, 'failed' => 失败条数, 'nodes' => 节点数,
     *                'skipped' => 是否因「已有实例在跑」而整体跳过]
     */
    public function refresh($force = false)
    {
        $summary = array('refreshed' => 0, 'failed' => 0, 'nodes' => 0, 'skipped' => false);

        if (!(int)config('v2board.extra_subscribe_enable', 0)) {
            return $summary;
        }

        $urls = $this->urls(null, true);
        // $urls 为空不能提前 return：配置里把链接全删掉时，要靠下面的清理把存储里的旧记录清掉
        // （记录含第三方凭据），否则它会永远留在 extra-subscribe.json 里；没有链接时 $due 为空，
        // 不发任何请求，只是把存储清空。

        // storage/app 在个别部署里可能不存在：先确保目录在，否则锁文件与存储文件都写不进去，功能静默失效
        $this->ensureStoreDir();

        // 同一时刻只允许一个实例真正拉取（定时任务与手动执行可能撞上）
        $lock = $this->lockStore();
        if (!$lock) {
            $summary['skipped'] = true;
            return $summary;
        }

        try {
            $store = $this->loadStore(true);
            $now = time();
            $interval = $this->refreshInterval();

            // 配置里已删除的链接：从文件里清掉
            $keep = array();
            foreach ($urls as $url) {
                $keep[md5($url)] = true;
            }
            $cleaned = false;
            if (!empty($store['urls']) && is_array($store['urls'])) {
                foreach (array_keys($store['urls']) as $key) {
                    if (!isset($keep[$key])) {
                        unset($store['urls'][$key]);
                        $cleaned = true;
                    }
                }
            }

            // 该刷新哪些：没数据 / 已过刷新间隔 / 上次失败已过重试间隔
            $due = array();
            foreach ($urls as $url) {
                $key = md5($url);
                $row = isset($store['urls'][$key]) ? $store['urls'][$key] : null;
                if ($force || $this->isDue($row, $now, $interval)) {
                    $due[$url] = $key;
                }
            }

            if ($due) {
                $this->fetchInto($store, $due, $now);
                foreach ($due as $url => $key) {
                    if (empty($store['urls'][$key]['error'])) {
                        $summary['refreshed']++;
                        $summary['nodes'] += (int)$store['urls'][$key]['node_count'];
                    } else {
                        $summary['failed']++;
                    }
                }
            }

            // 没有到期链接、也没有要清理的记录时不必重写文件：这条命令每分钟跑一次，无条件写等于每分钟 rename 一次
            if ($due || $cleaned) {
                $this->saveStore($store);
            }
        } catch (\Throwable $e) {
            Log::warning('extra subscribe: refresh failed - ' . $e->getMessage());
        } finally {
            $this->unlockStore($lock);
        }

        return $summary;
    }

    /**
     * 把当前配置里的链接标记为「该重新拉取了」（后台保存配置后调用）。
     * 不在这里直接 refresh()：① 会把后台保存卡住最长一个超时；② 同一请求进程里的 config()
     * 还是旧值。所以只把 last_attempt_at 置 0，让下一轮 extra:subscribe 判定为到期；
     * 不动 nodes，所以「标记」到「真正拉取」之间没有空窗。
     */
    public function markDue()
    {
        try {
            if (!(int)config('v2board.extra_subscribe_enable', 0)) {
                return false;
            }
            $urls = $this->urls();
            if (!$urls) {
                return false;
            }

            $this->ensureStoreDir();
            $lock = $this->lockStore();
            if (!$lock) {
                return false;   // 已有实例在刷新：它本来就会拉最新，不必抢锁
            }

            $changed = false;
            try {
                $store = $this->loadStore(true);
                foreach ($urls as $url) {
                    $key = md5($url);
                    // 没有记录的链接本来就是「到期」状态；这里只处理已有记录的
                    if (isset($store['urls'][$key])
                        && (int)$store['urls'][$key]['last_attempt_at'] !== 0) {
                        $store['urls'][$key]['last_attempt_at'] = 0;
                        $changed = true;
                    }
                }
                if ($changed) {
                    $this->saveStore($store);
                }
            } finally {
                $this->unlockStore($lock);
            }

            return $changed;
        } catch (\Throwable $e) {
            // 后台保存不能因为这一步失败而报错
            Log::warning('extra subscribe: mark due failed - ' . $this->maskText($e->getMessage()));
            return false;
        }
    }

    /**
     * 当前各链接的状态（供命令展示）
     */
    public function status()
    {
        $store = $this->loadStore(true);
        $now = time();
        $rows = array();

        foreach ($this->urls(null, true) as $url) {
            $key = md5($url);
            $row = isset($store['urls'][$key]) ? $store['urls'][$key] : array();
            $lastSuccess = isset($row['last_success_at']) ? (int)$row['last_success_at'] : null;
            $rows[] = array(
                'url'             => $this->maskUrl($url),
                'node_count'      => isset($row['node_count']) ? (int)$row['node_count'] : 0,
                'last_success_at' => $lastSuccess,
                'last_attempt_at' => isset($row['last_attempt_at']) ? (int)$row['last_attempt_at'] : null,
                'error'           => isset($row['error']) ? $row['error'] : null,
                // 与 nodes() 用同一套判据，否则「有上次成功时间、但节点是空的」会被谎报成「当前下发：是」
                'serving'         => $lastSuccess !== null && $lastSuccess + $this->maxStaleTtl() >= $now
                    && !empty($row['nodes']) && is_array($row['nodes']),
            );
        }

        return $rows;
    }

    /* ------------------------------------------------------------------
     |  下发路径（只读本地）
     * ------------------------------------------------------------------ */

    /**
     * 读取本地存储里的附加节点（不发任何请求）
     */
    private function nodes()
    {
        if (!(int)config('v2board.extra_subscribe_enable', 0)) {
            return array();
        }

        $urls = $this->urls();
        if (!$urls) {
            return array();
        }

        $store = $this->loadStore();
        $now = time();
        $nodes = array();

        foreach ($urls as $url) {
            $key = md5($url);
            if (empty($store['urls'][$key]['nodes']) || !is_array($store['urls'][$key]['nodes'])) {
                continue;
            }
            $row = $store['urls'][$key];
            $lastSuccess = (int)(isset($row['last_success_at']) ? $row['last_success_at'] : 0);
            // 上一次成功太久之前：宁可不发，也不下发一堆早已失效的节点
            if ($lastSuccess + $this->maxStaleTtl() < $now) {
                continue;
            }
            foreach ($row['nodes'] as $node) {
                $nodes[] = $node;
            }
        }

        return $nodes;
    }

    /* ------------------------------------------------------------------
     |  拉取路径（只在定时任务 / 手动执行时跑）
     * ------------------------------------------------------------------ */

    /**
     * 并发拉取 due 里的链接，并把结果写回 $store（失败保留原 nodes）。$due：url => cacheKey
     */
    private function fetchInto(&$store, $due, $now)
    {
        $client = new Client();
        $promises = array();

        foreach ($due as $url => $key) {
            // 仅允许 http/https；不通过则不请求，直接按失败记录。构造请求本身也可能抛（URL 形态奇怪），
            // 否则一条坏链接会把整批（其他链接）的刷新一起带崩。
            if (!$this->isUrlAllowed($url)) {
                $store['urls'][$key] = $this->failRow($store, $key, $url, $now, 'url not allowed');
                continue;
            }
            try {
                $promises[$url] = $client->getAsync($url, $this->requestOptions());
            } catch (\Throwable $e) {
                // 构造请求本身也可能抛（URL 形态奇怪等）：记成这条失败。
                // 否则一条坏链接会把整批（其他链接）的刷新一起带崩。
                $reason = $this->maskText($e->getMessage());
                Log::warning('extra subscribe: build request failed - ' . $this->maskUrl($url) . ' - ' . $reason);
                $store['urls'][$key] = $this->failRow($store, $key, $url, $now, $reason);
            }
        }

        // 不用 \GuzzleHttp\Promise\settle()：promises 2.0 已移除该函数（guzzle ^7.4.3 新装会解析到 2.x）。
        // 逐个 wait() 仍在同一 curl_multi 里，并发性不受影响，单条失败也不影响其他条。
        foreach ($promises as $url => $promise) {
            $key = $due[$url];

            try {
                $body = $this->readBody($promise->wait()->getBody());
                if ($body === null) {
                    Log::warning('extra subscribe: response too large - ' . $this->maskUrl($url));
                    $store['urls'][$key] = $this->failRow($store, $key, $url, $now, 'response too large');
                    continue;
                }

                $parsed = SubscriptionParser::parse($body);
                // 无条件记录节点数：成功但 0 节点时也要有日志，否则排查是黑盒
                Log::debug('extra subscribe: got ' . count($parsed['nodes']) . ' node(s), '
                    . strlen($body) . ' bytes, skipped=' . json_encode($parsed['skipped'])
                    . ' - ' . $this->maskUrl($url));

                if (!$parsed['nodes']) {
                    // 解析不出节点（空 body / 非 URI 列表等）：按失败处理并保留上一次成功的结果，别让一次抖动把已下发的节点清空
                    $store['urls'][$key] = $this->failRow($store, $key, $url, $now, 'no nodes parsed');
                    continue;
                }

                $store['urls'][$key] = array(
                    'url'             => $url,
                    'nodes'           => $parsed['nodes'],
                    'node_count'      => count($parsed['nodes']),
                    'skipped'         => $parsed['skipped'],
                    'error'           => null,
                    'last_attempt_at' => $now,
                    'last_success_at' => $now,
                );
            } catch (\Throwable $e) {
                // Guzzle 异常消息里带完整 URL（含 token）：整条消息里的 URL 一律打码后再落日志
                $reason = $this->maskText($e->getMessage());
                Log::warning('extra subscribe: fetch failed - ' . $this->maskUrl($url) . ' - ' . $reason);
                $store['urls'][$key] = $this->failRow($store, $key, $url, $now, $reason);
            }
        }
    }

    /**
     * 节点是否符合本项目自身的协议格式。三类直接丢：类型不在表里、缺任一必需字段
     * （渲染器会 500）、凭据为空（会退回本站用户 uuid → 必然连不上）。
     * 第四类：字段齐全但取值非法（见 $nodeValues）。
     */
    private static function nodeComplete($type, $node)
    {
        if (!isset(self::$nodeFields[$type]) || empty($node['_credential'])) {
            return false;
        }
        foreach (self::$nodeFields[$type] as $need) {
            if (!array_key_exists($need, $node)) {
                return false;
            }
        }
        // 键在、但取值不是数组：渲染器直接下标会抛 TypeError（见 $nodeArrayKeys）
        foreach (self::$nodeArrayKeys as $need) {
            if (array_key_exists($need, $node) && !is_array($node[$need])) {
                return false;
            }
        }
        if (isset(self::$nodeValues[$type])) {
            foreach (self::$nodeValues[$type] as $field => $allowed) {
                if (!in_array($node[$field], $allowed, true)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * 补齐「可选、但被渲染器无守护读取」的键（只补缺失的键，绝不改已有值）。
     * 存储跨版本存活（刷新失败时最长沿用 MAX_STALE_TTL），读到的可能是旧版解析器的形状。
     * 唯一确认可达的一处：reality 的 public_key / short_id（旧版 parseVless 里 sid 是条件写入，
     * 而 sid 本就可选）→ 缺了整份订阅 500；补的值就是解析器现在写的值。
     * 刻意不补 mport / obfs-host / obfs-path / obfs_password：核对过解析器全部历史版本，
     * 它们从首版起就与主键无条件同时写入，补只会掩盖手改坏的存储。
     */
    private static function repairOptionalKeys($type, array $node)
    {
        // reality 只出现在这两种协议里（tls=2 即 reality，见 parseVless / parseAnyTls）
        if (($type !== 'vless' && $type !== 'anytls') || !isset($node['tls']) || $node['tls'] != 2) {
            return $node;
        }
        foreach (array('tls_settings', 'tlsSettings') as $key) {
            // 非数组 / 空容器都不动：非数组交给 nodeComplete 的 $nodeArrayKeys 丢弃；空数组不是任何
            // 解析器版本会产出的形状，动它会翻转 ClashMeta `if ($tlsSettings)` 的真值、改变下发内容
            if (!isset($node[$key]) || !is_array($node[$key]) || !$node[$key]) {
                continue;
            }
            if (!array_key_exists('public_key', $node[$key])) {
                $node[$key]['public_key'] = '';
            }
            if (!array_key_exists('short_id', $node[$key])) {
                $node[$key]['short_id'] = '';
            }
        }

        return $node;
    }

    /**
     * 构造「失败」记录：保留上一次成功的 nodes，只更新 error 与 last_attempt_at
     */
    private function failRow($store, $key, $url, $now, $error)
    {
        $old = isset($store['urls'][$key]) ? $store['urls'][$key] : array();
        return array(
            'url'             => $url,
            'nodes'           => (isset($old['nodes']) && is_array($old['nodes'])) ? $old['nodes'] : array(),
            'node_count'      => isset($old['node_count']) ? (int)$old['node_count'] : 0,
            'skipped'         => isset($old['skipped']) ? $old['skipped'] : array(),
            'error'           => (string)$error,
            'last_attempt_at' => $now,
            'last_success_at' => isset($old['last_success_at']) ? $old['last_success_at'] : null,
        );
    }

    /**
     * 该条链接是否到了该刷新的时间（从没拉过 / 过了刷新间隔 / 上次失败已过重试间隔）
     */
    private function isDue($row, $now, $interval)
    {
        if (!is_array($row)) {
            return true; // 从没拉过
        }
        $last = (int)(isset($row['last_attempt_at']) ? $row['last_attempt_at'] : 0);
        if ($last > $now) {
            return true; // 时间戳在未来（改过服务器时间等）：别把自己卡成永不刷新
        }
        // 上次失败：短间隔重试；上次成功：按配置的刷新间隔
        $wait = empty($row['error']) ? $interval : min($interval, self::FAIL_RETRY_TTL);

        return $last + $wait <= $now;
    }

    /* ------------------------------------------------------------------
     |  本地存储
     * ------------------------------------------------------------------ */

    /**
     * 确保 storage/app 存在（个别部署里可能被清理；不存在则锁文件与存储文件都写不进去）
     */
    private function ensureStoreDir()
    {
        $dir = storage_path('app');
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
    }

    /**
     * 存储文件路径
     */
    private function storePath()
    {
        return storage_path('app/' . self::STORE_FILE);
    }

    /**
     * 读取存储文件（不存在 / 损坏一律当空，不影响本站节点下发）。
     * $fromRefresh=false：请求路径上传 false，否则文件一损坏每个订阅请求都刷一行日志。
     */
    private function loadStore($fromRefresh = false)
    {
        $empty = array('version' => 1, 'urls' => array());
        $path = $this->storePath();
        if (!is_file($path)) {
            return $empty;
        }
        $raw = @file_get_contents($path);
        if ($raw === false || trim($raw) === '') {
            return $empty;
        }
        $data = json_decode($raw, true);
        if (!is_array($data) || !isset($data['urls']) || !is_array($data['urls'])) {
            if ($fromRefresh) {
                Log::warning('extra subscribe: store file is broken, treat as empty');
            }
            return $empty;
        }

        return $data;
    }

    /**
     * 写存储文件：先写临时文件再 rename（原子替换），读方永远看不到写一半的内容
     */
    private function saveStore($store)
    {
        $path = $this->storePath();
        // JSON_INVALID_UTF8_SUBSTITUTE：第三方节点名可能是 GBK / 截断的 UTF-8，不加这个标志 json_encode 会整体返回 false → 一个节点都存不下来
        $json = json_encode($store, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
            | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json === false) {
            Log::warning('extra subscribe: encode store failed');
            return false;
        }
        $tmp = $path . '.tmp';
        if (@file_put_contents($tmp, $json) === false) {
            Log::warning('extra subscribe: write store failed');
            return false;
        }
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            Log::warning('extra subscribe: replace store failed');
            return false;
        }
        // 本文件由定时任务（可能是 root）写、web 用户读：显式放开读权限，免得 umask 0077 写成 0600 后 web 读不到
        @chmod($path, 0644);

        return true;
    }

    /**
     * 取独占锁：拿不到返回 null（「已有实例在跑」与「锁文件建不出来」两种原因在日志里分开）
     */
    private function lockStore()
    {
        $path = $this->storePath() . '.lock';
        $fp = @fopen($path, 'c');
        if (!$fp) {
            // 锁文件建不出来通常是 storage/app 权限问题，不能报成「已有实例在跑」
            Log::warning('extra subscribe: cannot open lock file (check storage/app permission) - ' . $path);
            return null;
        }
        if (!@flock($fp, LOCK_EX | LOCK_NB)) {
            fclose($fp);
            Log::debug('extra subscribe: refresh skipped, another run is in progress');
            return null;
        }

        return $fp;
    }

    /**
     * @param resource|null $fp
     */
    private function unlockStore($fp)
    {
        if (!$fp) {
            return;
        }
        @flock($fp, LOCK_UN);
        @fclose($fp);
    }

    /* ------------------------------------------------------------------
     |  配置与请求
     * ------------------------------------------------------------------ */

    /**
     * 读取额外订阅链接配置，拆成去重数组：一行一条（回车换行，不支持逗号），
     * 只做拆分 / 去重 / 限流，合法性交给 isUrlAllowed()。
     * $logLimit=false：请求路径上不记「超过上限」日志。
     */
    private function urls($raw = null, $logLimit = false)
    {
        if ($raw === null) {
            $raw = config('v2board.extra_subscribe_url', '');
        }

        if (is_array($raw)) {
            $lines = $raw;
        } else {
            $lines = preg_split('/[\r\n]+/', (string)$raw);
        }

        $urls = array();
        foreach ($lines as $line) {
            $line = trim((string)$line);
            if ($line === '' || in_array($line, $urls, true)) {
                continue;
            }
            $urls[] = $line;
        }

        if (count($urls) > self::MAX_URLS) {
            if ($logLimit) {
                Log::warning('extra subscribe: too many urls (' . count($urls)
                    . '), only the first ' . self::MAX_URLS . ' will be used');
            }
            $urls = array_slice($urls, 0, self::MAX_URLS);
        }

        return $urls;
    }

    /**
     * 刷新间隔（秒）：把后台「缓存时间」夹到 [MIN_REFRESH_TTL, MAX_REFRESH_TTL]。
     * 配置键 extra_subscribe_cache_ttl 是历史遗留名字（语义就是多久刷新一次），不改键名以免动
     * 后台 UI 与线上已有配置；后台表单的 min/max 引用同一批常量，两边不会漂移。
     */
    private function refreshInterval()
    {
        $interval = (int)config('v2board.extra_subscribe_cache_ttl', self::DEFAULT_REFRESH_TTL);
        if ($interval < self::MIN_REFRESH_TTL) {
            return self::MIN_REFRESH_TTL;
        }
        if ($interval > self::MAX_REFRESH_TTL) {
            return self::MAX_REFRESH_TTL;
        }

        return $interval;
    }

    /**
     * 上一次成功的结果最长沿用（秒）：取 MAX_STALE_TTL 与「刷新间隔 × 3」的大者 ——
     * 间隔可能被设得比 7 天还长，用小者会让节点在两次刷新之间静默消失。
     */
    private function maxStaleTtl()
    {
        $floor = $this->refreshInterval() * 3;

        return $floor > self::MAX_STALE_TTL ? $floor : self::MAX_STALE_TTL;
    }

    /**
     * URL 校验：仅允许 http / https
     */
    private function isUrlAllowed($url)
    {
        $parts = parse_url($url);
        if (!$parts || empty($parts['scheme']) || empty($parts['host'])) {
            Log::warning('extra subscribe: invalid url');
            return false;
        }
        if (!in_array(strtolower($parts['scheme']), array('http', 'https'), true)) {
            Log::warning('extra subscribe: scheme not allowed');
            return false;
        }

        return true;
    }

    /**
     * 构造请求选项
     */
    private function requestOptions()
    {
        // 本超时只在定时任务里等待（并发拉取，整批耗时≈最慢一条），不在用户请求路径上，
        // 所以给得宽一点：默认 15s，夹在 [3, 30]。
        $timeout = (int)config('v2board.extra_subscribe_timeout', self::DEFAULT_TIMEOUT);
        if ($timeout < self::MIN_TIMEOUT) {
            $timeout = self::MIN_TIMEOUT;
        }
        if ($timeout > self::MAX_TIMEOUT) {
            $timeout = self::MAX_TIMEOUT;
        }

        return array(
            'timeout'         => $timeout,
            'connect_timeout' => $timeout,
            // 不要加 'stream' => true：promise 收到响应头就 resolve，异步时 body 还没写入流 → readBody() 读到空串、0 节点
            'headers'         => array(
                'User-Agent' => 'v2board-extra-subscribe/1.0',
                'Accept'     => 'text/plain, */*',
            ),
        );
    }

    /**
     * 流式读取响应体并限制大小（避免大文件打爆内存）；超限返回 null
     */
    private function readBody($stream)
    {
        $body = '';
        while (!$stream->eof()) {
            $chunk = $stream->read(8192);
            if ($chunk === '') {
                break;
            }
            $body .= $chunk;
            if (strlen($body) > self::MAX_BODY_BYTES) {
                // 由调用方记录日志（带打码地址）
                return null;
            }
        }

        return $body;
    }

    /**
     * 给 URL 打码：丢掉 query（订阅 token 在这里）
     */
    private function maskUrl($url)
    {
        $parts = parse_url($url);
        if (!$parts || empty($parts['host'])) {
            return '(invalid url)';
        }

        $masked = (empty($parts['scheme']) ? 'http' : $parts['scheme']) . '://' . $parts['host'];
        if (!empty($parts['port'])) {
            $masked .= ':' . $parts['port'];
        }
        if (!empty($parts['path'])) {
            $masked .= $parts['path'];
        }

        return $masked;
    }

    /**
     * 把一段文本里所有 http(s) 地址打码：异常消息里出现的可能是跳转后的最终地址，
     * 只 str_replace($url, ...) 挡不住，token 会明文进日志。
     */
    private function maskText($text)
    {
        return preg_replace('#https?://[^\s"\'<>()]+#i', '(url masked)', (string)$text);
    }
}

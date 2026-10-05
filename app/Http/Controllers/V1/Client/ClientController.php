<?php

namespace App\Http\Controllers\V1\Client;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Protocols\General;
use App\Protocols\Singbox\Singbox;
use App\Protocols\Singbox\SingboxOld;
use App\Protocols\ClashMeta;
use App\Services\ExtraSubscriptionService;
use App\Services\ServerService;
use App\Services\TelegramService;
use App\Services\UserService;
use App\Utils\Helper;
use GuzzleHttp\Client;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class ClientController extends Controller
{
    public function subscribe(Request $request)
    {
        $flag = $request->input('flag')
            ?? ($_SERVER['HTTP_USER_AGENT'] ?? '');
        $flag = strtolower($flag);
        $user = $request->user;

        // Subscription link rate limit: reset UUID & subscribe URL when exceeded within a window
        if ((int)config('v2board.subscribe_limit_enable', 0)) {
            $limitCount = (int)config('v2board.subscribe_limit_count', 60);
            $limitExpire = (int)config('v2board.subscribe_limit_expire', 1);
            if ($limitExpire <= 0) {
                $limitExpire = 1;
            }
            $cacheKey = 'subscribe_limit_' . $user['id'];
            Cache::add($cacheKey, 0, $limitExpire * 60);
            $count = Cache::increment($cacheKey);
            if ($count > $limitCount) {
                $resetUser = User::find($user['id']);
                if ($resetUser) {
                    (new UserService())->resetSecurity($resetUser);
                    $resetUser->increment('subscribe_reset_count');
                    $message = "🔐订阅链接频率限制触发重置\n———————————————\n邮箱：\n`{$resetUser->email}`\n用户ID：\n`{$resetUser->id}`\nIP：\n`{$request->ip()}`\n窗口内拉取次数：\n`{$count}`\n累计触发重置：\n`{$resetUser->subscribe_reset_count}`\n时间：\n`" . date('Y-m-d H:i:s') . "`\n该账号因订阅拉取过于频繁，已自动重置UUID及订阅地址。";
                    (new TelegramService())->sendMessageWithAdmin($message, true);
                }
                Cache::forget($cacheKey);
                abort(403, __('Subscription has been reset due to too many requests, please refresh the subscription URL'));
            }
        }

        // account not expired and is not banned.
        $userService = new UserService();
        if ($userService->isAvailable($user)) {
            $serverService = new ServerService();
            // if custom subscribe URL is set, fetch subscription from it
            if (!empty($user->custom_subscribe_url)) {
                try {
                    $http = new Client();
                    $response = $http->get($user->custom_subscribe_url, [
                        'timeout' => 15,
                        'headers' => [
                            'User-Agent' => $request->header('User-Agent', '')
                        ]
                    ]);
                    $body = (string)$response->getBody();
                    return response($body, 200)->withHeaders([
                        'Content-Type' => $response->getHeaderLine('Content-Type') ?: 'text/plain; charset=utf-8'
                    ]);
                } catch (\Exception $e) {
                    $servers = [];
                }
            } else {
                $servers = $serverService->getAvailableServers($user);

                // 合并「额外订阅」节点：按节点名去重（本站优先），拉取失败静默降级，只在下发本站节点这条
                // 路径上合并。custom_subscribe_url 是给异常用户用的「替换」通道（原样透传、不过本站渲染），
                // 附加订阅不得参与 —— 否则该用户仍能拿到可用的第三方节点，与「剥夺原有节点」的目的相悖。
                $servers = (new ExtraSubscriptionService())->merge($servers);
            }

            if($flag) {
                if (!strpos($flag, 'sing')) {
                    $this->setSubscribeInfoToServers($servers, $user);
                    foreach (array_reverse(glob(app_path('Protocols') . '/*.php')) as $file) {
                        $file = 'App\\Protocols\\' . basename($file, '.php');
                        $class = new $file($user, $servers);
                        if (strpos($flag, $class->flag) !== false) {
                            return $class->handle();
                        }
                    }
                }
                if (strpos($flag, 'sing') !== false) {
                    $version = null;
                    if (preg_match('/sing-box\s+([0-9.]+)/i', $flag, $matches)) {
                        $version = $matches[1];
                    }
                    if (!is_null($version) && $version >= '1.12.0') {
                        $class = new Singbox($user, $servers);
                    } else {
                        $class = new SingboxOld($user, $servers);
                    }
                    return $class->handle();
                }
            }
            $class = new General($user, $servers);
            return $class->handle();
        }
    }

    private function setSubscribeInfoToServers(&$servers, $user)
    {
        if (!isset($servers[0])) return;
        if (!(int)config('v2board.show_info_to_server_enable', 0)) return;
        $useTraffic = $user['u'] + $user['d'];
        $totalTraffic = $user['transfer_enable'];
        $remainingTraffic = Helper::trafficConvert($totalTraffic - $useTraffic);
        $expiredDate = $user['expired_at'] ? date('Y-m-d', $user['expired_at']) : '长期有效';
        $userService = new UserService();
        $resetDay = $userService->getResetDay($user);
        array_unshift($servers, array_merge($servers[0], [
            'name' => "套餐到期：{$expiredDate}",
        ]));
        if ($resetDay) {
            array_unshift($servers, array_merge($servers[0], [
                'name' => "距离下次重置剩余：{$resetDay} 天",
            ]));
        }
        array_unshift($servers, array_merge($servers[0], [
            'name' => "剩余流量：{$remainingTraffic}",
        ]));
    }
}

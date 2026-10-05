<?php

namespace App\Http\Requests\Admin;

use App\Services\ExtraSubscriptionService;
use Illuminate\Foundation\Http\FormRequest;

class ConfigSave extends FormRequest
{
    const RULES = [
        // deposit
        'deposit_bounus' => [
            'nullable',
            'array',
        ],
        // invite & commission
        'ticket_status' => 'in:0,1,2',
        'invite_force' => 'in:0,1',
        'invite_commission' => 'integer',
        'invite_gen_limit' => 'integer',
        'invite_never_expire' => 'in:0,1',
        'commission_first_time_enable' => 'in:0,1',
        'commission_auto_check_enable' => 'in:0,1',
        'commission_withdraw_limit' => 'nullable|numeric',
        'commission_withdraw_method' => 'nullable|array',
        'withdraw_close_enable' => 'in:0,1',
        'commission_distribution_enable' => 'in:0,1',
        'commission_distribution_l1' => 'nullable|numeric',
        'commission_distribution_l2' => 'nullable|numeric',
        'commission_distribution_l3' => 'nullable|numeric',
        // site
        'logo' => 'nullable|url',
        'force_https' => 'in:0,1',
        'stop_register' => 'in:0,1',
        'app_name' => '',
        'app_description' => '',
        'app_url' => 'nullable|url',
        'subscribe_url' => 'nullable',
        'subscribe_path' => 'nullable|regex:/^\\//',
        'try_out_enable' => 'in:0,1',
        'try_out_plan_id' => 'integer',
        'try_out_hour' => 'numeric',
        'tos_url' => 'nullable|url',
        'currency' => '',
        'currency_symbol' => '',
        // subscribe
        'plan_change_enable' => 'in:0,1',
        'reset_traffic_method' => 'in:0,1,2,3,4',
        'surplus_enable' => 'in:0,1',
        'allow_new_period' => 'in:0,1',
        'new_order_event_id' => 'in:0,1',
        'renew_order_event_id' => 'in:0,1',
        'change_order_event_id' => 'in:0,1',
        'show_info_to_server_enable' => 'in:0,1',
        'show_subscribe_method' => 'in:0,1,2',
        'show_subscribe_expire' => 'nullable|integer',
        'subscribe_limit_enable' => 'in:0,1',
        'subscribe_limit_count' => 'nullable|integer',
        'subscribe_limit_expire' => 'nullable|integer',
        // extra subscribe（附加订阅节点：把额外订阅的节点拼接在本站节点之后下发）
        // 多行字符串（一行一条链接），不能用 url 规则，改在 rules() 里逐行校验；
        // 必须写成数组：rules() 会往这个键上追加闭包，写成字符串会 Fatal error（[] operator not supported）
        'extra_subscribe_enable' => 'in:0,1',
        // 多行字符串（一行一条链接），所以不能用 url 规则，改在 rules() 里逐行校验。
        //    必须写成**数组**：rules() 会往这个键上追加闭包，
        //    若写成字符串会触发 Fatal error: [] operator not supported for strings
        'extra_subscribe_url' => [
            'nullable',
            'string',
            'max:5000',
        ],
        // 服务层会把这两个值夹紧（refreshInterval / requestOptions），这里引用同一批常量，
        // 免得「后台允许填的值」与「服务端实际生效的值」各写一份而漂移
        'extra_subscribe_cache_ttl' => 'nullable|integer|min:' . ExtraSubscriptionService::MIN_REFRESH_TTL
            . '|max:' . ExtraSubscriptionService::MAX_REFRESH_TTL,
        'extra_subscribe_timeout' => 'nullable|integer|min:' . ExtraSubscriptionService::MIN_TIMEOUT
            . '|max:' . ExtraSubscriptionService::MAX_TIMEOUT,
        // server
        'server_api_url' => 'nullable|string',
        'server_token' => 'nullable|min:16',
        'server_pull_interval' => 'integer',
        'server_push_interval' => 'integer',
        'device_limit_mode' => 'in:0,1',
        'server_node_report_min_traffic' => 'integer', 
        'server_device_online_min_traffic' => 'integer', 
        // frontend
        'frontend_theme' => '',
        'frontend_theme_sidebar' => 'nullable|in:dark,light',
        'frontend_theme_header' => 'nullable|in:dark,light',
        'frontend_theme_color' => 'nullable|in:default,darkblue,black,green',
        'frontend_background_url' => 'nullable|url',
        // email
        'email_template' => '',
        'email_host' => '',
        'email_port' => '',
        'email_username' => '',
        'email_password' => '',
        'email_encryption' => '',
        'email_from_address' => '',
        // telegram
        'telegram_bot_enable' => 'in:0,1',
        'telegram_bot_token' => '',
        'telegram_discuss_id' => '',
        'telegram_channel_id' => '',
        'telegram_discuss_link' => 'nullable|url',
        // app
        'android_version' => '',
        'android_download_url' => '',
        'linux_version' => '',
        'linux_download_url' => '',
        'macos_version' => '',
        'macos_download_url' => '',
        'windows_version' => '',
        'windows_download_url' => '',
        // safe
        'email_whitelist_enable' => 'in:0,1',
        'email_whitelist_suffix' => 'nullable|array',
        'email_format_strict_enable' => 'in:0,1',
        'recaptcha_enable' => 'in:0,1',
        'recaptcha_key' => '',
        'recaptcha_site_key' => '',
        'email_verify' => 'in:0,1',
        'safe_mode_enable' => 'in:0,1',
        'register_limit_by_ip_enable' => 'in:0,1',
        'register_limit_count' => 'integer',
        'register_limit_expire' => 'integer',
        'secure_path' => 'min:8|regex:/^[\w-]*$/',
        'password_limit_enable' => 'in:0,1',
        'password_limit_count' => 'integer',
        'password_limit_expire' => 'integer',
    ];
    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {
        $rules = self::RULES;

        $rules['deposit_bounus'][] = function ($attribute, $value, $fail) {
            foreach ($value as $tier) {
                if (!preg_match('/^\d+(\.\d+)?:\d+(\.\d+)?$/', $tier)) {
                    if($tier == '') {
                        continue;
                    }
                    $fail('充值奖励格式不正确，必须为充值金额:奖励金额');
                }
            }
        };

        // 额外订阅链接是**多行字符串**（回车换行），逐行校验（空行跳过）
        $rules['extra_subscribe_url'][] = function ($attribute, $value, $fail) {
            $count = 0;
            $seen = array();
            foreach (preg_split('/[\r\n]+/', (string)$value) as $line) {
                $line = trim($line);
                if ($line === '') {
                    continue;
                }
                if (!preg_match('#^https?://[^\s]+$#i', $line)) {
                    $fail('额外订阅链接格式不正确，必须为 http(s):// 开头的完整地址（一行一条）');
                    return;
                }
                // 按去重后的条数计（服务端 urls() 会去重），否则「10 条链接里粘贴了 1 条重复」会被误报超上限
                if (isset($seen[$line])) {
                    continue;
                }
                $seen[$line] = true;
                $count++;
            }
            // 与服务端 MAX_URLS 对齐：原来超过上限只是服务端静默丢弃，这里直接拒绝，管理员当场就知道
            if ($count > ExtraSubscriptionService::MAX_URLS) {
                $fail('额外订阅链接最多 ' . ExtraSubscriptionService::MAX_URLS
                    . ' 条（当前 ' . $count . ' 条）');
            }
        };
        return $rules;
    }

    public function messages()
    {
        // illiteracy prompt
        return [
            'app_url.url' => '站点URL格式不正确，必须携带http(s)://',
            'subscribe_url.url' => '订阅URL格式不正确，必须携带http(s)://',
            'subscribe_path.regex' => '订阅路径必须以/开头',
            'server_token.min' => '通讯密钥长度必须大于16位',
            'tos_url.url' => '服务条款URL格式不正确，必须携带http(s)://',
            'telegram_discuss_link.url' => 'Telegram群组地址必须为URL格式，必须携带http(s)://',
            'logo.url' => 'LOGO URL格式不正确，必须携带https(s)://',
            'secure_path.min' => '后台路径长度最小为8位',
            'secure_path.regex' => '后台路径只能为字母或数字',
            'extra_subscribe_cache_ttl.min' => '缓存时间最小为 ' . ExtraSubscriptionService::MIN_REFRESH_TTL . ' 秒',
            'extra_subscribe_cache_ttl.max' => '缓存时间最大为 ' . ExtraSubscriptionService::MAX_REFRESH_TTL . ' 秒（1 天）',
            'extra_subscribe_timeout.min' => '请求超时最小为 ' . ExtraSubscriptionService::MIN_TIMEOUT . ' 秒',
            'extra_subscribe_timeout.max' => '请求超时最大为 ' . ExtraSubscriptionService::MAX_TIMEOUT . ' 秒',
        ];
    }
}

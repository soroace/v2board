<?php

namespace App\Console\Commands;

use App\Services\ExtraSubscriptionService;
use Illuminate\Console\Command;

/**
 * 拉取「额外订阅」链接的节点并保存到本地：下发路径（ExtraSubscriptionService::merge）
 * 只读本地文件、不发请求，所以靠这条命令定期预取；由 Kernel::schedule 每分钟调度。
 */
class ExtraSubscribe extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'extra:subscribe
        {--force : 忽略刷新间隔，强制重拉全部链接}
        {--status : 只显示当前状态，不拉取}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = '拉取「额外订阅」链接的节点并保存到本地（订阅下发时只读本地）';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        $service = new ExtraSubscriptionService();

        if ($this->option('status')) {
            $this->showStatus($service->status());
            return;
        }

        if (!(int)config('v2board.extra_subscribe_enable', 0)) {
            // 定时任务每分钟跑一次：未启用时保持安静，只在人工执行时提示
            if ($this->output->isDecorated()) {
                $this->warn('额外订阅未启用（后台「订阅设置」→「附加订阅」），本轮不拉取。');
            }
            return;
        }

        $result = $service->refresh($this->option('force') ? true : false);

        if ($result['skipped']) {
            $this->warn('本轮跳过：已有刷新实例在跑，或锁文件不可写（后者看 storage/logs/laravel.log）。');
        } elseif ($result['refreshed'] || $result['failed']) {
            $this->info('刷新完成：成功 ' . $result['refreshed'] . ' 条，失败 '
                . $result['failed'] . ' 条，共 ' . $result['nodes'] . ' 个节点。');
        }

        // 本命令由 schedule 每分钟调度一次：没有实际动作时不要输出，否则 cron 日志会被刷屏；
        // 人工在终端执行（或加 --status）时照常打印完整状态。
        if ($this->output->isDecorated() || $result['refreshed'] || $result['failed']) {
            $this->showStatus($service->status());
        }
    }

    /**
     * 打印各链接状态
     */
    private function showStatus($rows)
    {
        if (!$rows) {
            $this->warn('没有配置额外订阅链接（后台「订阅设置」→「额外订阅」）。');
            return;
        }

        $table = array();
        foreach ($rows as $row) {
            $table[] = array(
                $row['url'],
                $row['node_count'],
                $row['last_success_at'] ? date('Y-m-d H:i:s', $row['last_success_at']) : '-',
                $row['last_attempt_at'] ? date('Y-m-d H:i:s', $row['last_attempt_at']) : '-',
                $row['serving'] ? '是' : '否',
                $row['error'] ? $row['error'] : '',
            );
        }

        $this->table(
            array('链接', '节点数', '上次成功', '上次尝试', '当前下发', '最近错误'),
            $table
        );
    }
}

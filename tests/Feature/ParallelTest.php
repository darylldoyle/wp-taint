<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Scan\WorkerPool;
use Enshrined\WpTaint\Taint\AnalysisOptions;

/**
 * `--jobs` must be a pure speed knob.
 *
 * A scanner whose answer depends on how many cores it was given is a scanner
 * nobody can baseline, so the contract is byte-identical output at every job
 * count — not "roughly the same findings".
 *
 * Two things make that hold: the interprocedural rounds read a frozen summary
 * table, so no worker can observe another's output, and every merge happens in
 * shard order rather than completion order.
 */

/**
 * @return array{findings: list<string>, warnings: int}
 */
function scanTreeWithJobs(string $directory, int $jobs): array
{
    $result = (new Scanner(
        testRegistry(),
        new AnalysisOptions(),
        $directory,
        structuralRulesEnabled: true,
        taintGraphPath: null,
        jobs: $jobs,
    ))->scan((new FileFinder())->find([$directory]));

    return [
        'findings' => array_map(
            static fn (object $finding): string => implode('|', [
                $finding->ruleId,
                $finding->file,
                (string) $finding->line,
                (string) $finding->column,
                $finding->fingerprint,
                (string) count($finding->trace),
                implode(
                    '>',
                    array_map(static fn (object $step): string => $step->verb->value . '@' . $step->line, $finding->trace),
                ),
            ]),
            $result->findings->all(),
        ),
        'warnings' => count($result->warnings),
    ];
}

function parallelFixtureTree(): string
{
    $directory = sys_get_temp_dir() . '/wp-taint-parallel-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);

    // Enough cross-file interprocedural flow that sharding could plausibly
    // change the answer if the rounds were not frozen.
    file_put_contents($directory . '/helpers.php', <<<'PHP'
        <?php
        function acme_wrap($value) { return '<span>' . $value . '</span>'; }
        function acme_row($value) { return '<td>' . acme_wrap($value) . '</td>'; }
        function acme_escape($value) { return esc_html($value); }
        PHP);

    file_put_contents($directory . '/render.php', <<<'PHP'
        <?php
        class AcmeRenderer
        {
            private $title;

            public function capture() { $this->title = $_GET['title']; }
            public function render() { echo acme_row($this->title); }
            public function safe() { echo acme_row(acme_escape($_GET['other'])); }
        }
        PHP);

    file_put_contents($directory . '/db.php', <<<'PHP'
        <?php
        global $wpdb;
        $order = $_GET['orderby'];
        $wpdb->get_results("SELECT * FROM {$wpdb->prefix}items ORDER BY {$order}");
        $wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->prefix}items WHERE id = %d", absint($_GET['id'])));
        PHP);

    file_put_contents($directory . '/routes.php', <<<'PHP'
        <?php
        register_rest_route('acme/v1', '/a', ['methods' => 'POST', 'callback' => 'acme_a']);
        add_action('wp_ajax_acme_b', 'acme_b');
        function acme_b() { update_option('acme', $_POST['v']); }
        PHP);

    return $directory;
}

it('produces byte-identical findings at every job count', function (): void {
    if (! WorkerPool::isSupported()) {
        expect(true)->toBeTrue('pcntl unavailable; --jobs falls back to serial');

        return;
    }

    $directory = parallelFixtureTree();

    try {
        $serial = scanTreeWithJobs($directory, 1);

        expect($serial['findings'])->not->toBeEmpty();

        foreach ([2, 3, 4, 8] as $jobs) {
            expect(scanTreeWithJobs($directory, $jobs))->toBe(
                $serial,
                sprintf('--jobs=%d disagreed with --jobs=1', $jobs),
            );
        }
    } finally {
        foreach (glob($directory . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($directory);
    }
});

it('falls back to serial rather than failing when only one job is asked for', function (): void {
    $results = (new WorkerPool(1))->run(static fn (int $shard, int $count): array => [$shard, $count]);

    expect($results)->toBe([[0, 1]]);
});

it('returns one result per shard, in shard order', function (): void {
    if (! WorkerPool::isSupported()) {
        expect(true)->toBeTrue('pcntl unavailable');

        return;
    }

    $results = (new WorkerPool(4))->run(static fn (int $shard, int $count): string => $shard . '/' . $count);

    expect($results)->toBe(['0/4', '1/4', '2/4', '3/4']);
});

it('surfaces a worker that dies rather than silently losing its shard', function (): void {
    if (! WorkerPool::isSupported()) {
        expect(true)->toBeTrue('pcntl unavailable');

        return;
    }

    // Losing a shard silently would drop findings, which is the one failure
    // mode a security scanner must never have.
    expect(static fn (): array => (new WorkerPool(3))->run(static function (int $shard): string {
        if ($shard === 1) {
            throw new RuntimeException('worker exploded');
        }

        return 'ok';
    }))->toThrow(RuntimeException::class, 'exited abnormally');
});

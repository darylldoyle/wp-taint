<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Cli\MemoryScanProgress;
use Enshrined\WpTaint\Cli\ProjectScanConfig;
use Enshrined\WpTaint\Cli\ScanConfiguration;
use Enshrined\WpTaint\Taint\FunctionBodies;
use Symfony\Component\Console\Output\BufferedOutput;

it('reads a memory budget as a size or as unlimited', function (string $value, ?int $bytes): void {
    expect(ScanConfiguration::memoryBudget($value))->toBe($bytes);
})->with([
    ['4G', 4 * 1024 * 1024 * 1024],
    ['512m', 512 * 1024 * 1024],
    ['750KB', 750 * 1024],
    ['1000', 1000],
    ['0', 0],
    ['unlimited', null],
    [' Unlimited ', null],
]);

it('rejects a memory budget it cannot read', function (string $value): void {
    ScanConfiguration::memoryBudget($value);
})->with(['', 'lots', '4T', '-1', '1.5G'])->throws(InvalidArgumentException::class);

it('reads memory_budget from the project config', function (): void {
    $file = tempnam(sys_get_temp_dir(), 'wp-taint-toml');
    file_put_contents($file, "[scan]\n[scan.options]\nmemory_budget = \"512M\"\n");

    try {
        expect(ProjectScanConfig::load($file)->memoryBudget)->toBe('512M');
    } finally {
        unlink($file);
    }
});

it('reports a note only under --debug-memory', function (): void {
    $output = new BufferedOutput();
    (new MemoryScanProgress($output))->note('graph cache after setup: 1MB held of 4,096MB');

    expect($output->fetch())->toBe("[memory] graph cache after setup: 1MB held of 4,096MB\n");
});

it('gives the room an AST took back to the budget once the AST is released', function (): void {
    $path = dirname(__DIR__) . '/Fixtures/vulnerable/ajax-missing-capability-check.php';
    $result = (new CfgBuilder(dirname($path)))->buildFromFile($path);
    $file = $result->file();

    $bodies = new FunctionBodies(null, PHP_INT_MAX);
    $bodies->add($file);
    $withAst = $bodies->held();
    $bodies->releaseAst($path);

    expect($withAst)->toBe((int) filesize($path) * 100);
    expect($bodies->held())->toBe((int) filesize($path) * 60);
});

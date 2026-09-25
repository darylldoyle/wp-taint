<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// A function's body rebuilt from source must analyse exactly as the body built
// the first time. That is what lets a scan drop graphs under a memory budget:
// see docs/design/two-pass-engine.md. A budget of zero rebuilds every body
// every time it is needed, the harshest case, and must change nothing a reader
// can see.
//
// tools/compare-budget.php holds the corpus to this.

/** @return list<mixed> */
function scanWithBudget(string $directory, ?int $budget, int $jobs = 1): array
{
    $result = (new Scanner(
        testRegistry(),
        new AnalysisOptions(),
        $directory,
        jobs: $jobs,
        memoryBudget: $budget,
    ))->scan((new FileFinder())->find([$directory]));

    return [
        array_map(serialize(...), $result->findings->all()),
        array_map(serialize(...), $result->warnings),
        $result->unresolvedHooks,
    ];
}

/** @return array<string, array{string}> */
function rebuildFixtures(): array
{
    $root = dirname(__DIR__, 2);
    $cases = [];

    foreach (glob($root . '/ideas/wp-taint-analyser-fixtures/fixtures/*/*/*', GLOB_ONLYDIR) ?: [] as $dir) {
        $cases[substr($dir, strlen($root) + 1)] = [$dir];
    }

    return $cases;
}

it('analyses a rebuilt body exactly as the original, on a multi-file fixture', function (string $directory): void {
    expect(scanWithBudget($directory, 0))->toBe(scanWithBudget($directory, null));
})->with(rebuildFixtures());

it('analyses rebuilt bodies exactly as the originals, on every single-file fixture at once', function (): void {
    $directory = dirname(__DIR__) . '/Fixtures/vulnerable';

    expect(scanWithBudget($directory, 0))->toBe(scanWithBudget($directory, null));
});

it('analyses rebuilt bodies exactly as the originals with four workers', function (): void {
    $directory = dirname(__DIR__) . '/Fixtures/vulnerable';

    expect(scanWithBudget($directory, 0, 4))->toBe(scanWithBudget($directory, null, 4));
});

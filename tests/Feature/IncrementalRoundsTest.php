<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// Incremental rounds must be a pure speed knob, the same contract as --jobs:
// re-analysing only the functions whose reads changed has to produce exactly
// what re-analysing everything produces. Not the same count. The same findings,
// the same traces, the same warnings.
//
// tools/compare-incremental.php holds the corpus to this; these hold the
// fixtures to it on every run.

function scanBothWays(string $directory, int $jobs = 1): array
{
    $files = (new FileFinder())->find([$directory]);
    $results = [];

    foreach ([false, true] as $incremental) {
        $result = (new Scanner(
            testRegistry(),
            new AnalysisOptions(incrementalRounds: $incremental),
            $directory,
            jobs: $jobs,
        ))->scan($files);

        // Each finding serialised on its own: serialize() writes back
        // references for shared objects, so the list as a whole can differ in
        // representation between two runs that report exactly the same.
        $results[] = [
            array_map(serialize(...), $result->findings->all()),
            array_map(serialize(...), $result->warnings),
            $result->unresolvedHooks,
        ];
    }

    return $results;
}

/** @return array<string, array{string}> */
function multiFileFixtures(): array
{
    $cases = [];

    $root = dirname(__DIR__, 2);

    foreach (glob($root . '/ideas/wp-taint-analyser-fixtures/fixtures/*/*/*', GLOB_ONLYDIR) ?: [] as $dir) {
        $cases[substr($dir, strlen($root) + 1)] = [$dir];
    }

    return $cases;
}

it('gives the same result either way on a multi-file fixture', function (string $directory): void {
    [$full, $incremental] = scanBothWays($directory);

    expect($incremental)->toBe($full);
})->with(multiFileFixtures());

it('gives the same result either way on every single-file fixture scanned as one program', function (): void {
    // Several fixtures declare the same helper, which is the duplicate-body
    // path; a single program of 290 files is also the widest set of reads.
    [$full, $incremental] = scanBothWays(dirname(__DIR__) . '/Fixtures/vulnerable');

    expect($incremental)->toBe($full);
});

it('gives the same result either way with four workers', function (): void {
    [$full, $incremental] = scanBothWays(dirname(__DIR__) . '/Fixtures/vulnerable', 4);

    expect($incremental)->toBe($full);
});

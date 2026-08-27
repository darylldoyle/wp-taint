<?php

/**
 * Records, and checks, what the pinned corpus reports.
 *
 * The fixture suite proves the engine finds what it should on code written to
 * be found. It cannot prove anything about the shapes real plugins are made of,
 * and by the end of the remediation work the corpus had caught seventeen bugs
 * the fixtures never saw — including two that made findings *fall*, which is
 * the direction nobody thinks to look in.
 *
 * The one that prompted this: per-key array taint took the corpus down
 * seventeen findings, every mover downward, and it was a false negative —
 * `effectiveTaintOf()` had stopped seeing keyed slots at call boundaries. The
 * only reason it was caught is that somebody happened to read the numbers.
 *
 * So the numbers are committed, and a change that moves them has to say so.
 *
 * ## What a diff here means
 *
 * Not "a regression". A count moving is exactly what a real improvement looks
 * like too. It means *look*: run the plugin that moved, read the traces that
 * appeared or vanished, and either accept the new number into the baseline with
 * the reason in the commit message, or fix what moved it.
 *
 * A count that falls deserves more suspicion than one that rises. A false
 * positive is visible and annoying; a false negative is silent.
 *
 * Usage:
 *   php tools/corpus-baseline.php [--check]
 */

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Enshrined\WpTaint\Registry\RegistryLoader;
use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;

const LOCK = __DIR__ . '/../tests/Fixtures/corpus-lock.json';
const BASELINE = __DIR__ . '/../tests/Fixtures/corpus-baseline.json';
const CORPUS = __DIR__ . '/../tests/Fixtures/corpus';

$check = in_array('--check', $argv, true);

$lockBody = file_get_contents(LOCK);

if ($lockBody === false) {
    fwrite(STDERR, "Cannot read tests/Fixtures/corpus-lock.json.\n");

    exit(1);
}

/** @var array{plugins?: array<string, string>} $lock */
$lock = json_decode($lockBody, true, 512, JSON_THROW_ON_ERROR);
$plugins = $lock['plugins'] ?? [];
ksort($plugins);

$missing = [];

foreach (array_keys($plugins) as $slug) {
    if (! is_dir(CORPUS . '/' . $slug)) {
        $missing[] = $slug;
    }
}

if ($missing !== []) {
    fwrite(STDERR, sprintf(
        "Pinned plugins are not present: %s\nRun: composer corpus:lock\n",
        implode(', ', $missing),
    ));

    exit(1);
}

$registry = (new RegistryLoader(__DIR__ . '/../registries'))->load('wordpress')->configured(true, false);
$actual = [];

foreach ($plugins as $slug => $version) {
    $root = CORPUS . '/' . $slug;

    // Serial. A worker that runs out of memory takes its whole shard with it,
    // and a baseline that depends on how much RAM the runner had is not a
    // baseline. WPForms Lite already does this at --jobs=4.
    $result = (new Scanner($registry, new AnalysisOptions(), $root, jobs: 1))
        ->scan((new FileFinder())->find([$root]));

    $bySeverity = [];

    foreach ($result->findings->all() as $finding) {
        $key = $finding->severity->value;
        $bySeverity[$key] = ($bySeverity[$key] ?? 0) + 1;
    }

    ksort($bySeverity);

    $actual[$slug] = [
        'version' => $version,
        'findings' => count($result->findings->all()),
        'bySeverity' => $bySeverity,
        'warnings' => count($result->warnings),
        'parseFailures' => count($result->parseErrors),
    ];

    printf(
        "  %-24s %-10s findings=%-4d warnings=%-2d parseFailures=%d\n",
        $slug,
        $version,
        $actual[$slug]['findings'],
        $actual[$slug]['warnings'],
        $actual[$slug]['parseFailures'],
    );
}

$encoded = json_encode($actual, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";

if (! $check) {
    file_put_contents(BASELINE, $encoded);

    printf("\nWrote tests/Fixtures/corpus-baseline.json.\n");

    exit(0);
}

$stored = is_file(BASELINE) ? file_get_contents(BASELINE) : false;
$expected = $stored === false ? '' : $stored;

if ($expected === $encoded) {
    printf("\nThe corpus matches its baseline.\n");

    exit(0);
}

fwrite(STDERR, "\nThe corpus no longer matches its baseline.\n\n");

/** @var array<string, array{findings: int, warnings: int, parseFailures: int}> $previous */
$previous = $expected === '' ? [] : json_decode($expected, true, 512, JSON_THROW_ON_ERROR);

foreach ($actual as $slug => $row) {
    $was = $previous[$slug]['findings'] ?? null;

    if ($was === $row['findings']) {
        continue;
    }

    fwrite(STDERR, sprintf(
        "  %-24s findings %s -> %d%s\n",
        $slug,
        $was === null ? '(new)' : (string) $was,
        $row['findings'],
        $was !== null && $row['findings'] < $was ? '   <- fell; check for a false negative' : '',
    ));
}

fwrite(
    STDERR,
    "\nA moved count is not automatically a regression, and not automatically fine.\n"
        . "Read the traces that appeared or vanished, then either fix the cause or run\n"
        . "`composer corpus:baseline` and put the reason in the commit message.\n",
);

exit(1);

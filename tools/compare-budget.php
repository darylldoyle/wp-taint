<?php

/**
 * Checks that a memory budget changes nothing but memory and time.
 *
 * Each target is scanned twice: with no budget, holding every graph, and with a
 * budget, rebuilding from source every graph it does not hold. The two results
 * are compared in full: every finding, its trace, and every warning. Any
 * difference is listed and the exit status is 1. A budget of zero, the default
 * here, rebuilds every body every time it is needed. Run it over the corpus
 * before changing anything a rebuilt body depends on; see
 * docs/design/two-pass-engine.md.
 *
 * A target is a directory, scanned as one program, or a wp-taint.toml, scanned
 * with its paths, reference trees and excludes.
 *
 * Usage:
 *   php tools/compare-budget.php [--budget=BYTES] <directory|wp-taint.toml>...
 */

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Enshrined\WpTaint\Cli\ProjectScanConfig;
use Enshrined\WpTaint\Registry\RegistryLoader;
use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Scan\ScanResult;
use Enshrined\WpTaint\Taint\AnalysisOptions;

$budget = 0;
$targets = [];

foreach (array_slice($argv, 1) as $argument) {
    if (str_starts_with($argument, '--budget=')) {
        $budget = (int) substr($argument, 9);

        continue;
    }

    $targets[] = $argument;
}

if ($targets === []) {
    fwrite(STDERR, "Usage: php tools/compare-budget.php [--budget=BYTES] <directory|wp-taint.toml>...\n");

    exit(2);
}

$registry = (new RegistryLoader(__DIR__ . '/../registries'))->load('wordpress')->configured(true, false);
$different = 0;

foreach ($targets as $target) {
    if (str_ends_with($target, '.toml')) {
        $config = ProjectScanConfig::load($target);
        $paths = $config->paths;
        $reference = $config->reference;
        $files = (new FileFinder($config->excludes))->find($paths);
        $root = '/';
    } else {
        $paths = [$target];
        $reference = [];
        $files = (new FileFinder())->find($paths);
        $root = $target;
    }

    $scan = static function (?int $memoryBudget) use ($registry, $root, $reference, $files): array {
        $start = hrtime(true);
        $result = (new Scanner(
            $registry,
            new AnalysisOptions(),
            $root,
            jobs: 1,
            includePaths: $reference,
            memoryBudget: $memoryBudget,
        ))->scan($files);

        return [$result, (hrtime(true) - $start) / 1e9];
    };

    [$full, $fullSeconds] = $scan(null);
    [$budgeted, $budgetedSeconds] = $scan($budget);

    $same = fingerprintOf($full) === fingerprintOf($budgeted);
    $different += $same ? 0 : 1;

    printf(
        "%-10s %-50s findings %5d / %5d   unlimited %7.1fs   budget %s %7.1fs\n",
        $same ? 'identical' : 'DIFFERENT',
        basename($target),
        count($full->findings->all()),
        count($budgeted->findings->all()),
        $fullSeconds,
        number_format($budget),
        $budgetedSeconds,
    );

    if (! $same) {
        describeDifference($full, $budgeted);
    }
}

exit($different === 0 ? 0 : 1);

/**
 * Everything a reader could see: each finding with its whole trace, and each
 * warning. Serialised, because the trace's taint sets keep their state in
 * private properties that a JSON encoding would drop.
 *
 * One at a time, never the list as a whole: serialize() writes a back
 * reference for an object it has already seen, so two runs that report the
 * same things but share a trace step or taint set between findings differently
 * would compare unequal. WooCommerce did exactly that, with every one of its
 * 303 findings identical.
 */
function fingerprintOf(ScanResult $result): string
{
    return serialize([
        array_map(serialize(...), $result->findings->all()),
        array_map(serialize(...), $result->warnings),
        $result->unresolvedHooks,
    ]);
}

function describeDifference(ScanResult $full, ScanResult $budgeted): void
{
    $index = static function (ScanResult $result): array {
        $byFingerprint = [];

        foreach ($result->findings->all() as $finding) {
            $byFingerprint[$finding->fingerprint] = serialize($finding);
        }

        return $byFingerprint;
    };

    $a = $index($full);
    $b = $index($budgeted);

    foreach (array_keys(array_diff_key($a, $b)) as $fingerprint) {
        echo "    only with no budget: {$fingerprint}\n";
    }

    foreach (array_keys(array_diff_key($b, $a)) as $fingerprint) {
        echo "    only with the budget: {$fingerprint}\n";
    }

    foreach (array_intersect_key($a, $b) as $fingerprint => $serialized) {
        if ($serialized !== ($b[$fingerprint] ?? null)) {
            echo "    same finding, different trace: {$fingerprint}\n";
        }
    }

    if (serialize($full->warnings) !== serialize($budgeted->warnings)) {
        printf(
            "    warnings: %d with no budget, %d with the budget\n",
            count($full->warnings),
            count($budgeted->warnings),
        );
    }
}

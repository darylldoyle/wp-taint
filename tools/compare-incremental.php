<?php

/**
 * Checks that incremental rounds produce exactly what full rounds produce.
 *
 * Each target is scanned twice, re-analysing only the functions whose reads
 * changed and re-analysing every function every round, and the two results
 * are compared in full: every finding, its trace, and every warning. Any
 * difference is listed and the exit status is 1. Run it over the corpus before
 * changing anything the ReadLog depends on; an incremental round that skips a
 * function whose input moved loses findings silently.
 *
 * A target is a directory, scanned as one program, or a wp-taint.toml, scanned
 * with its paths, reference trees and excludes.
 *
 * Usage:
 *   php tools/compare-incremental.php <directory|wp-taint.toml>...
 */

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Enshrined\WpTaint\Cli\ProjectScanConfig;
use Enshrined\WpTaint\Registry\RegistryLoader;
use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Scan\ScanResult;
use Enshrined\WpTaint\Taint\AnalysisOptions;

$targets = array_slice($argv, 1);

if ($targets === []) {
    fwrite(STDERR, "Usage: php tools/compare-incremental.php <directory|wp-taint.toml>...\n");

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

    $scan = static function (bool $incremental) use ($registry, $root, $reference, $files): array {
        $start = hrtime(true);
        $result = (new Scanner(
            $registry,
            new AnalysisOptions(incrementalRounds: $incremental),
            $root,
            jobs: 1,
            includePaths: $reference,
        ))->scan($files);

        return [$result, (hrtime(true) - $start) / 1e9];
    };

    [$full, $fullSeconds] = $scan(false);
    [$incremental, $incrementalSeconds] = $scan(true);

    $same = fingerprintOf($full) === fingerprintOf($incremental);
    $different += $same ? 0 : 1;

    printf(
        "%-10s %-50s findings %5d / %5d   full %7.1fs   incremental %7.1fs\n",
        $same ? 'identical' : 'DIFFERENT',
        basename($target),
        count($full->findings->all()),
        count($incremental->findings->all()),
        $fullSeconds,
        $incrementalSeconds,
    );

    if (! $same) {
        describeDifference($full, $incremental);
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

function describeDifference(ScanResult $full, ScanResult $incremental): void
{
    $index = static function (ScanResult $result): array {
        $byFingerprint = [];

        foreach ($result->findings->all() as $finding) {
            $byFingerprint[$finding->fingerprint] = serialize($finding);
        }

        return $byFingerprint;
    };

    $a = $index($full);
    $b = $index($incremental);

    foreach (array_keys(array_diff_key($a, $b)) as $fingerprint) {
        echo "    only with full rounds:        {$fingerprint}\n";
    }

    foreach (array_keys(array_diff_key($b, $a)) as $fingerprint) {
        echo "    only with incremental rounds: {$fingerprint}\n";
    }

    foreach (array_intersect_key($a, $b) as $fingerprint => $serialized) {
        if ($serialized !== ($b[$fingerprint] ?? null)) {
            echo "    same finding, different trace: {$fingerprint}\n";
        }
    }

    if (serialize($full->warnings) !== serialize($incremental->warnings)) {
        printf(
            "    warnings: %d with full rounds, %d incremental\n",
            count($full->warnings),
            count($incremental->warnings),
        );
    }
}

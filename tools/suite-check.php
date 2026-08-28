<?php

/**
 * Scores the engine against two third-party fixture suites.
 *
 * Everything else this project measures itself against was written here, or has
 * no answer key. These two have both: labelled vulnerable/safe pairs, written
 * by someone else, against a contract stated independently of the engine.
 *
 * They also cover semantics the other benchmarks do not — context correctness,
 * escape invalidation, weak sanitisers posing as real ones — rather than
 * incidents, which is what the CVE set covers.
 *
 * ## wp-taint-fixtures
 *
 * 109 annotations across 18 rule ids, Semgrep's `ruleid:` / `ok:` grammar,
 * scored by its own `tools/score.py` with per-rule precision and recall. Our
 * SARIF goes in unmodified.
 *
 * ## ideas/wp-taint-analyser-fixtures
 *
 * 36 scenarios as vulnerable/safe pairs, cross-file and cross-plugin, scored by
 * its own comparator against canonical finding kinds. Needs an adapter, because
 * it names findings by contract rather than by our rule ids — the mapping lives
 * in `tools/suite-adapter.php` and is deliberately conservative: `output.
 * unescaped` and `flow.unsanitized_unescaped` are the same claim framed from
 * either end, so the fixture's own label applies, while `output.
 * escape_invalidated` is a distinct claim only our own rule may earn.
 *
 * Usage:
 *   php tools/suite-check.php [--check]
 *
 * `--check` fails when either score drops below the recorded baseline, which is
 * what makes this useful in CI rather than merely interesting.
 */

declare(strict_types=1);

const BASELINE = __DIR__ . '/../tests/Fixtures/suite-baseline.json';
const ROOT = __DIR__ . '/..';

$check = in_array('--check', $argv, true);
$results = [];

// ---------------------------------------------------------------------------
// wp-taint-fixtures: our SARIF, their scorer.
// ---------------------------------------------------------------------------

$sarif = tempnam(sys_get_temp_dir(), 'wp-taint-suite') . '.sarif';

exec(sprintf(
    '%s %s scan %s --stored-taint-writes --format=sarif -o %s --fail-on=never 2>&1',
    escapeshellarg(PHP_BINARY),
    escapeshellarg(ROOT . '/bin/wp-taint'),
    escapeshellarg(ROOT . '/wp-taint-fixtures'),
    escapeshellarg($sarif),
), $output, $status);

if ($status !== 0) {
    fwrite(STDERR, "Scan of wp-taint-fixtures failed:\n" . implode("\n", $output) . "\n");

    exit(1);
}

exec(sprintf(
    'python3 %s %s 2>&1',
    escapeshellarg(ROOT . '/wp-taint-fixtures/tools/score.py'),
    escapeshellarg($sarif),
), $scored);

@unlink($sarif);

$summary = null;

foreach ($scored as $line) {
    if (str_starts_with(trim($line), 'OVERALL')) {
        $split = preg_split('/\s+/', trim($line));
        $summary = $split === false ? [] : $split;
    }
}

if ($summary === null || count($summary) < 8) {
    fwrite(STDERR, "Could not read a score from wp-taint-fixtures.\n" . implode("\n", $scored) . "\n");

    exit(1);
}

$results['wp-taint-fixtures'] = [
    'truePositives' => (int) $summary[1],
    'falseNegatives' => (int) $summary[2],
    'falsePositives' => (int) $summary[3],
    'trueNegatives' => (int) $summary[4],
];

printf(
    "  wp-taint-fixtures          TP=%d FN=%d FP=%d TN=%d\n",
    ...array_values($results['wp-taint-fixtures']),
);

// ---------------------------------------------------------------------------
// ideas/wp-taint-analyser-fixtures: our adapter, their comparator.
// ---------------------------------------------------------------------------

$suite = ROOT . '/ideas/wp-taint-analyser-fixtures';

if (is_dir($suite)) {
    $actual = tempnam(sys_get_temp_dir(), 'wp-taint-adapter') . '.json';

    exec(sprintf(
        '%s %s %s 2>&1',
        escapeshellarg(PHP_BINARY),
        escapeshellarg(__DIR__ . '/suite-adapter.php'),
        escapeshellarg($actual),
    ), $adapted, $status);

    if ($status !== 0) {
        fwrite(STDERR, "Adapter failed:\n" . implode("\n", $adapted) . "\n");

        exit(1);
    }

    exec(sprintf(
        'python3 %s %s 2>&1',
        escapeshellarg($suite . '/tools/compare_results.py'),
        escapeshellarg($actual),
    ), $compared);

    @unlink($actual);

    $missing = 0;
    $unexpected = 0;
    $bucket = null;

    foreach ($compared as $line) {
        if (str_contains($line, 'Missing findings')) {
            $bucket = 'missing';
        } elseif (str_contains($line, 'Unexpected findings')) {
            $bucket = 'unexpected';
        } elseif (str_starts_with(trim($line), '- ')) {
            $bucket === 'missing' ? $missing++ : $unexpected++;
        }
    }

    $results['analyser-fixtures'] = ['missing' => $missing, 'unexpected' => $unexpected];

    printf("  ideas/analyser-fixtures    missing=%d unexpected=%d\n", $missing, $unexpected);
}

$encoded = json_encode($results, JSON_PRETTY_PRINT) . "\n";

if (! $check) {
    file_put_contents(BASELINE, $encoded);
    printf("\nWrote tests/Fixtures/suite-baseline.json.\n");

    exit(0);
}

$stored = is_file(BASELINE) ? file_get_contents(BASELINE) : false;

if (($stored === false ? '' : $stored) === $encoded) {
    printf("\n  Both suites match their recorded score.\n");

    exit(0);
}

/** @var array<string, array<string, int>> $previous */
$previous = $stored === false ? [] : json_decode($stored, true, 512, JSON_THROW_ON_ERROR);

fwrite(STDERR, "\nA third-party suite score moved:\n\n");

foreach ($results as $suiteName => $row) {
    foreach ($row as $metric => $value) {
        $was = $previous[$suiteName][$metric] ?? null;

        if ($was === $value) {
            continue;
        }

        $worse = in_array($metric, ['falseNegatives', 'falsePositives', 'missing', 'unexpected'], true)
            ? $value > (int) $was
            : $value < (int) $was;

        fwrite(STDERR, sprintf(
            "  %-26s %-16s %s -> %d%s\n",
            $suiteName,
            $metric,
            $was === null ? '(new)' : (string) $was,
            $value,
            $worse ? '   <- worse' : '',
        ));
    }
}

fwrite(
    STDERR,
    "\nBetter is good news and wants the baseline rewriting with a reason. Worse\n"
        . "means a third party's labelled case stopped working: read it before accepting.\n",
);

exit(1);

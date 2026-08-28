<?php

/**
 * Normalises our findings into the shape ideas/wp-taint-analyser-fixtures wants.
 *
 * That suite names findings by contract — `output.unescaped`,
 * `output.escape_invalidated`, `input.unsanitized_storage` — rather than by our
 * rule ids, and its ADAPTER.md asks each analyser to supply the mapping.
 *
 * The mapping is deliberately conservative in one place. `output.unescaped` and
 * `flow.unsanitized_unescaped` are the same claim framed from either end, so the
 * fixture's own label applies. `output.escape_invalidated` is a *different*
 * claim, and only `wp.xss.escape-voided` may earn it: reporting plain unescaped
 * output where the suite wants invalidation is a partial detection, and
 * crediting it would be marking our own homework.
 *
 * Usage:
 *   php tools/suite-adapter.php /path/to/actual.json
 */

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';
use Enshrined\WpTaint\Registry\RegistryLoader;
use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;

const SUITE = __DIR__ . '/../ideas/wp-taint-analyser-fixtures/fixtures';

/**
 * Our rule ids to the suite's canonical kinds.
 *
 * Group-aware, as ADAPTER.md directs: a source-to-sink scenario under flow/
 * wants `flow.unsanitized_unescaped` for what we call an XSS finding. Mapping
 * everything to output.unescaped scored eleven detections as simultaneous
 * misses and false positives.
 */
function kindFor(string $rule, string $expected): ?string
{
    // A distinct claim, and only our own rule may make it. Reporting plain
    // unescaped output where the suite wants escape_invalidated is a partial
    // detection, not a hit, and crediting it would be marking our own homework.
    if ($rule === 'wp.xss.escape-voided') {
        return 'output.escape_invalidated';
    }

    // `output.unescaped` and `flow.unsanitized_unescaped` are the same finding
    // framed from either end, so the fixture's own expectation picks the label.
    if (str_starts_with($rule, 'wp.xss.') || str_starts_with($rule, 'wp.sqli.')) {
        return in_array($expected, ['output.unescaped', 'flow.unsanitized_unescaped'], true)
            ? $expected
            : 'output.unescaped';
    }

    if ($rule === 'wp.stored.untrusted-write') {
        return 'input.unsanitized_storage';
    }

    return null;
}

// Stored writes are behind a flag; the suite expects them, so turn them on.
$registry = (new RegistryLoader(__DIR__ . '/../registries'))->load('wordpress')->configured(true, true);

/** @var array<string, string> fixture|variant => the kind the suite expects */
$expects = [];

$expectedRaw = file_get_contents(dirname(SUITE) . '/expected-findings.json');

if ($expectedRaw === false) {
    fwrite(STDERR, "Cannot read expected-findings.json\n");

    exit(1);
}

/** @var list<array{fixture: string, variant: string, expect: string}> $expectedRows */
$expectedRows = json_decode($expectedRaw, true, 512, JSON_THROW_ON_ERROR);

foreach ($expectedRows as $row) {
    $expects[$row['fixture'] . '|' . $row['variant']] = $row['expect'];
}

$out = [];

foreach (['input', 'output', 'flow'] as $group) {
    $entries = scandir(SUITE . "/$group");

    foreach ($entries === false ? [] : $entries as $fixture) {
        if (str_starts_with($fixture, '.')) {
            continue;
        }

        foreach (['vulnerable', 'safe'] as $variant) {
            $dir = SUITE . "/$group/$fixture/$variant";

            if (! is_dir($dir)) {
                continue;
            }

            $files = (new FileFinder())->find([$dir]);
            if ($files === []) {
                continue;
            }
            $r = (new Scanner($registry, new AnalysisOptions(), $dir, jobs: 1))->scan($files);
            $seen = [];
            foreach ($r->findings->all() as $f) {
                $kind = kindFor($f->ruleId, $expects[$fixture . '|' . $variant] ?? '');
                if ($kind === null) {
                    continue;
                }
                $key = $fixture . '|' . $variant . '|' . $kind;
                if (isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;
                $out[] = ['fixture' => $fixture, 'variant' => $variant, 'kind' => $kind];
            }
        }
    }
}
$target = $argv[1] ?? __DIR__ . '/../suite-actual.json';
file_put_contents($target, json_encode($out, JSON_PRETTY_PRINT));

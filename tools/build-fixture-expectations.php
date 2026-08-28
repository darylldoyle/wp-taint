<?php

/**
 * Regenerates the `<name>.expected.json` sibling of every fixture from the
 * inline `// wp-taint-expect <rule-id> <kind>` annotations in the fixture
 * itself.
 *
 * The annotation is the thing a human edits, because it sits on the sink line
 * and therefore cannot drift out of sync with it. The JSON is what the harness
 * reads, because the plan specifies a machine-readable expectation file.
 * `tests/Fixture/ExpectationsAreInSyncTest.php` fails if the two disagree, so
 * there is no way to change one and forget the other.
 *
 * Usage: php tools/build-fixture-expectations.php [--check]
 */

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../tests/Pest.php';

const ANNOTATION = '/\/\/\s*wp-taint-expect\s+(?<rule>[a-z0-9._-]+)\s+(?<kind>[a-z_]+)\s*$/';

/**
 * @return array{expectation: string, findings: list<array{ruleId: string, kind: string, line: int}>}
 */
function buildExpectation(string $path, string $expectation): array
{
    $lines = file($path, FILE_IGNORE_NEW_LINES);

    if ($lines === false) {
        throw new RuntimeException(sprintf('Unable to read fixture %s.', $path));
    }

    $findings = [];

    foreach ($lines as $index => $line) {
        if (preg_match(ANNOTATION, $line, $matches) !== 1) {
            continue;
        }

        $findings[] = [
            'ruleId' => $matches['rule'],
            'kind' => $matches['kind'],
            'line' => $index + 1,
        ];
    }

    usort($findings, static fn (array $a, array $b): int => [$a['line'], $a['ruleId']] <=> [$b['line'], $b['ruleId']]);

    return [
        'expectation' => $expectation,
        'findings' => $findings,
    ];
}

/**
 * @param array{expectation: string, findings: list<array{ruleId: string, kind: string, line: int}>} $expectation
 */
function encode(array $expectation): string
{
    return json_encode($expectation, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
}

$check = in_array('--check', $argv, true);
$root = dirname(__DIR__) . '/tests/Fixtures';
$drifted = [];
$written = 0;

foreach (['vulnerable', 'safe'] as $expectation) {
    $paths = glob($root . '/' . $expectation . '/*.php');

    if ($paths === false) {
        throw new RuntimeException(sprintf('Unable to list %s fixtures.', $expectation));
    }

    sort($paths);

    foreach ($paths as $path) {
        $built = buildExpectation($path, $expectation);
        $target = preg_replace('/\.php$/', '.expected.json', $path);

        if ($target === null) {
            throw new RuntimeException(sprintf('Unable to derive expectation path for %s.', $path));
        }

        if ($expectation === 'vulnerable' && $built['findings'] === []) {
            throw new RuntimeException(sprintf(
                'Fixture %s is in vulnerable/ but carries no wp-taint-expect annotation. '
                    . 'Every vulnerable fixture must state what it expects.',
                basename($path),
            ));
        }

        if ($expectation === 'safe' && $built['findings'] !== []) {
            throw new RuntimeException(sprintf(
                'Fixture %s is in safe/ but carries a wp-taint-expect annotation. '
                    . 'Safe fixtures expect zero findings by definition.',
                basename($path),
            ));
        }

        $encoded = encode($built);
        $current = is_file($target) ? file_get_contents($target) : null;

        if ($current === $encoded) {
            continue;
        }

        if ($check) {
            $drifted[] = basename($target);

            continue;
        }

        file_put_contents($target, $encoded);
        $written++;
    }
}

if ($check && $drifted !== []) {
    fwrite(STDERR, sprintf(
        "Fixture expectations are out of date:\n  %s\n\nRun: composer fixtures:build\n",
        implode("\n  ", $drifted),
    ));

    exit(1);
}

if ($check) {
    echo "Fixture expectations are in sync.\n";

    exit(0);
}

printf("Wrote %d expectation file%s.\n", $written, $written === 1 ? '' : 's');

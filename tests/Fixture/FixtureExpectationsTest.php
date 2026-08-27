<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\ScanResult;

/**
 * The regression suite that matters.
 *
 * `safe/` is the important half. A tool that cries wolf gets muted and then
 * deleted, so a single false positive here fails the build.
 */

/**
 * @return array<string, array{0: string, 1: string}> keyed by fixture name
 */
function fixtureCases(string $bucket): array
{
    $paths = glob(fixturePath($bucket) . '/*.php');
    $paths = $paths === false ? [] : $paths;
    sort($paths);

    $cases = [];

    foreach ($paths as $path) {
        // Key each case by its fixture name so a failure names the file rather
        // than an index.
        $cases[$bucket . '/' . basename($path, '.php')] = [$bucket, basename($path, '.php')];
    }

    return $cases;
}

/**
 * @return array{expectation: string, findings: list<array{ruleId: string, kind: string, line: int}>}
 */
function fixtureExpectation(string $bucket, string $name): array
{
    $path = fixturePath($bucket . '/' . $name . '.expected.json');

    expect($path)->toBeFile();

    /** @var array{expectation: string, findings: list<array{ruleId: string, kind: string, line: int}>} $decoded */
    $decoded = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);

    return $decoded;
}

/**
 * @return list<array{ruleId: string, kind: string, line: int}>
 */
function actualFindings(ScanResult $result): array
{
    return array_map(
        static fn (object $finding): array => [
            'ruleId' => $finding->ruleId,
            'kind' => $finding->kind->value,
            'line' => $finding->line,
        ],
        $result->findings->all(),
    );
}

it('detects every vulnerable fixture exactly as annotated', function (string $bucket, string $name): void {
    $result = scanFixture($bucket . '/' . $name . '.php');

    expect($result->parseErrors)->toBe([], sprintf('%s failed to parse', $name));
    expect(actualFindings($result))->toBe(
        fixtureExpectation($bucket, $name)['findings'],
        sprintf('%s/%s did not match its wp-taint-expect annotations', $bucket, $name),
    );
})->with(fixtureCases('vulnerable'));

it('reports nothing at all on the safe fixtures', function (string $bucket, string $name): void {
    $result = scanFixture($bucket . '/' . $name . '.php');

    expect($result->parseErrors)->toBe([], sprintf('%s failed to parse', $name));
    expect(actualFindings($result))->toBe(
        [],
        sprintf(
            '%s/%s produced a false positive. Safe fixtures are the ones that matter: '
                . 'a scanner that cries wolf gets muted and then deleted.',
            $bucket,
            $name,
        ),
    );
})->with(fixtureCases('safe'));

it('gives every finding a complete trace ending at the sink', function (string $bucket, string $name): void {
    foreach (scanFixture($bucket . '/' . $name . '.php')->findings as $finding) {
        expect($finding->trace)->not->toBeEmpty(
            sprintf('%s: %s has no trace', $name, $finding->ruleId),
        );

        $trace = $finding->trace;
        $last = $trace[count($trace) - 1];

        expect($last->verb->value)->toBe('sink', sprintf('%s: trace does not end at a sink', $name));
        expect($last->line)->toBe($finding->line, sprintf('%s: sink step is not at the finding line', $name));
    }
})->with(fixtureCases('vulnerable'));

it('meets the success criteria for the fixture suite', function (): void {
    $vulnerable = fixtureCases('vulnerable');
    $safe = fixtureCases('safe');

    // The plan sets a floor of 40 each. Falling below it means coverage was
    // deleted rather than the engine improving.
    expect(count($vulnerable))->toBeGreaterThanOrEqual(40);
    expect(count($safe))->toBeGreaterThanOrEqual(40);

    $caught = 0;

    foreach ($vulnerable as [$bucket, $name]) {
        $result = scanFixture($bucket . '/' . $name . '.php');
        $expected = fixtureExpectation($bucket, $name)['findings'];

        if (actualFindings($result) === $expected) {
            $caught++;
        }
    }

    $rate = $caught / count($vulnerable);

    expect($rate)->toBeGreaterThanOrEqual(
        0.9,
        sprintf('True positive rate is %.1f%%, below the 90%% the plan requires.', $rate * 100),
    );
});

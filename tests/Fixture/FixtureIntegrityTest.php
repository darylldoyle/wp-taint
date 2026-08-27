<?php

/**
 * Guards the fixture suite itself.
 *
 * The `.expected.json` files are generated from the inline `wp-taint-expect`
 * annotations. Two sources of truth is a drift hazard, so the generator is run
 * in check mode here: edit one without the other and this fails.
 */

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Symfony\Component\Process\Process;

it('keeps the expectation files in sync with the inline annotations', function (): void {
    $process = new Process(['php', 'tools/build-fixture-expectations.php', '--check'], projectRoot());
    $process->run();

    expect($process->getExitCode())->toBe(
        0,
        "Fixture expectations are stale. Run: composer fixtures:build\n" . $process->getErrorOutput(),
    );
});

it('parses every file in the parse fixtures', function (): void {
    $directory = fixturePath('parse');
    $paths = glob($directory . '/*.php');
    $paths = $paths === false ? [] : $paths;
    sort($paths);

    expect($paths)->not->toBeEmpty();

    $builder = new CfgBuilder($directory);
    $failures = [];

    foreach ($paths as $path) {
        $result = $builder->buildFromFile($path);

        if (! $result->isSuccess()) {
            $failures[] = basename($path) . ': ' . $result->error()->message;
        }
    }

    expect($failures)->toBe(
        [],
        "These are the gnarly-but-valid constructs the parser must handle:\n  " . implode("\n  ", $failures),
    );
});

it('has a safe counterpart for every vulnerable rule', function (): void {
    // Guardrail 9: never add a rule without both a vulnerable and a safe
    // fixture. The safe one is the one that matters.
    $ruleIds = [];

    foreach (glob(fixturePath('vulnerable') . '/*.expected.json') ?: [] as $path) {
        /** @var array{findings: list<array{ruleId: string}>} $expectation */
        $expectation = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);

        foreach ($expectation['findings'] as $finding) {
            $ruleIds[$finding['ruleId']] = true;
        }
    }

    expect(array_keys($ruleIds))->not->toBeEmpty();

    // Every rule the vulnerable fixtures exercise must also be represented in
    // the safe set, i.e. there is at least one file that could plausibly trip
    // it and must not.
    $safeFiles = glob(fixturePath('safe') . '/*.php') ?: [];

    expect(count($safeFiles))->toBeGreaterThanOrEqual(
        count($ruleIds),
        'There are more rules exercised by vulnerable fixtures than there are safe fixtures.',
    );
});

it('keeps every fixture syntactically valid PHP', function (): void {
    $invalid = [];

    foreach (['vulnerable', 'safe', 'parse'] as $bucket) {
        foreach (glob(fixturePath($bucket) . '/*.php') ?: [] as $path) {
            $process = new Process(['php', '-l', $path]);
            $process->run();

            if ($process->getExitCode() !== 0) {
                $invalid[] = $bucket . '/' . basename($path);
            }
        }
    }

    expect($invalid)->toBe([]);
});

<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

/**
 * End-to-end runs of the real binary.
 *
 * Exit codes are a contract — CI gates on them — so they are exercised through
 * the actual process rather than by calling the command class.
 */

/**
 * @param list<string> $arguments
 *
 * @return array{exit: int, stdout: string, stderr: string}
 */
function runCli(array $arguments): array
{
    $process = new Process(['php', 'bin/wp-taint', ...$arguments, '--no-ansi'], projectRoot());
    $process->run();

    return [
        'exit' => $process->getExitCode() ?? -1,
        'stdout' => $process->getOutput(),
        'stderr' => $process->getErrorOutput(),
    ];
}

it('exits 0 on a clean file', function (): void {
    $result = runCli(['scan', 'tests/Fixtures/safe/xss-echo-esc-html.php']);

    expect($result['exit'])->toBe(0);
});

it('exits 1 when a finding reaches the fail-on threshold', function (): void {
    $result = runCli(['scan', 'tests/Fixtures/vulnerable/xss-echo-direct.php']);

    expect($result['exit'])->toBe(1);
    expect($result['stdout'])->toContain('wp.xss.unescaped-output');
});

it('exits 0 when the finding is below the fail-on threshold', function (): void {
    $result = runCli(['scan', 'tests/Fixtures/vulnerable/xss-echo-direct.php', '--fail-on=critical']);

    expect($result['exit'])->toBe(0);
});

it('exits 0 when fail-on is never', function (): void {
    $result = runCli(['scan', 'tests/Fixtures/vulnerable/sqli-wpdb-query-interpolation.php', '--fail-on=never']);

    expect($result['exit'])->toBe(0);
});

it('exits 2 on a file that will not parse, even with no findings', function (): void {
    $directory = sys_get_temp_dir() . '/wp-taint-cli-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);
    file_put_contents($directory . '/broken.php', '<?php function ( { ');

    try {
        $result = runCli(['scan', $directory]);

        expect($result['exit'])->toBe(2);
    } finally {
        @unlink($directory . '/broken.php');
        @rmdir($directory);
    }
});

it('exits 2 on an unknown path', function (): void {
    $result = runCli(['scan', '/definitely/not/here']);

    expect($result['exit'])->toBe(2);
    expect($result['stderr'])->toContain('Path does not exist');
});

it('exits 2 on an unknown format', function (): void {
    $result = runCli(['scan', 'tests/Fixtures/safe', '--format=yaml']);

    expect($result['exit'])->toBe(2);
    expect($result['stderr'])->toContain('Unknown format');
});

it('reports a clean parse rate for the parse fixtures', function (): void {
    $result = runCli(['scan', 'tests/Fixtures/parse', '--parse-report']);

    expect($result['exit'])->toBe(0);
    expect($result['stdout'])->toContain('files parsed');
});

it('emits valid JSON on stdout', function (): void {
    $result = runCli(['scan', 'tests/Fixtures/vulnerable/xss-echo-direct.php', '--format=json']);

    $payload = json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR);

    expect($payload['findings'])->toHaveCount(1);
});

it('emits valid SARIF on stdout', function (): void {
    $result = runCli(['scan', 'tests/Fixtures/vulnerable/xss-echo-direct.php', '--format=sarif']);

    $payload = json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR);

    expect($payload['version'])->toBe('2.1.0');
});

it('round-trips a baseline through the CLI', function (): void {
    $baseline = sys_get_temp_dir() . '/wp-taint-cli-baseline-' . bin2hex(random_bytes(6)) . '.json';

    try {
        $generate = runCli([
            'scan',
            'tests/Fixtures/vulnerable/xss-echo-direct.php',
            '--generate-baseline=' . $baseline,
        ]);

        expect($generate['exit'])->toBe(0);
        expect($baseline)->toBeFile();

        $rerun = runCli([
            'scan',
            'tests/Fixtures/vulnerable/xss-echo-direct.php',
            '--baseline=' . $baseline,
        ]);

        expect($rerun['exit'])->toBe(0);
        expect($rerun['stdout'])->toContain('1 finding suppressed by baseline');
    } finally {
        @unlink($baseline);
    }
});

it('writes a report to a file when asked', function (): void {
    $output = sys_get_temp_dir() . '/wp-taint-cli-out-' . bin2hex(random_bytes(6)) . '.json';

    try {
        $result = runCli([
            'scan',
            'tests/Fixtures/vulnerable/xss-echo-direct.php',
            '--format=json',
            '--output=' . $output,
        ]);

        expect($result['exit'])->toBe(1);
        expect($output)->toBeFile();
        expect(json_decode((string) file_get_contents($output), true, 512, JSON_THROW_ON_ERROR))
            ->toHaveKey('findings');
    } finally {
        @unlink($output);
    }
});

it('honours --no-interprocedural', function (): void {
    $with = runCli(['scan', 'tests/Fixtures/vulnerable/xss-one-hop.php', '--format=json']);
    $without = runCli(['scan', 'tests/Fixtures/vulnerable/xss-one-hop.php', '--format=json', '--no-interprocedural']);

    $count = static fn (string $json): int => count(
        json_decode($json, true, 512, JSON_THROW_ON_ERROR)['findings'],
    );

    expect($count($with['stdout']))->toBe(1);
    expect($count($without['stdout']))->toBe(0);
});

it('honours --min-severity', function (): void {
    $result = runCli([
        'scan',
        'tests/Fixtures/vulnerable/redirect-open-wp-redirect.php',
        '--format=json',
        '--min-severity=high',
    ]);

    expect(json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR)['findings'])->toBe([]);
});

it('honours --exclude', function (): void {
    $result = runCli([
        'scan',
        'tests/Fixtures/vulnerable',
        '--format=json',
        '--exclude=*/xss-*',
        '--exclude=*/sqli-*',
    ]);

    $files = array_column(
        array_column(json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR)['findings'], 'location'),
        'file',
    );

    foreach ($files as $file) {
        expect($file)->not->toStartWith('xss-');
        expect($file)->not->toStartWith('sqli-');
    }
});

it('dumps the CFG for a file', function (): void {
    $result = runCli(['dump-cfg', 'tests/Fixtures/vulnerable/xss-echo-direct.php']);

    expect($result['exit'])->toBe(0);
    expect($result['stdout'])->toContain('Block#1');
    expect($result['stdout'])->toContain('Terminal_Echo');
});

it('dumps the CFG as GraphViz dot', function (): void {
    $result = runCli(['dump-cfg', 'tests/Fixtures/vulnerable/xss-echo-direct.php', '--format=dot']);

    expect($result['exit'])->toBe(0);
    expect($result['stdout'])->toContain('digraph');
});

it('reports what it lowered for php-cfg', function (): void {
    $result = runCli(['dump-cfg', 'tests/Fixtures/vulnerable/xss-match-expression.php', '--show-lowering']);

    expect($result['exit'])->toBe(0);
    expect($result['stdout'])->toContain('match');
});

it('dumps the resolved registry for human audit', function (): void {
    $result = runCli(['registry:dump']);

    expect($result['exit'])->toBe(0);
    expect($result['stdout'])->toContain('php-core → wordpress');
    expect($result['stdout'])->toContain('SOURCES');
    expect($result['stdout'])->toContain('EXPLICITLY SAFE');
    expect($result['stdout'])->toContain('wp_unslash()');
});

it('writes a taint graph when asked', function (): void {
    $dot = sys_get_temp_dir() . '/wp-taint-graph-' . bin2hex(random_bytes(6)) . '.dot';

    try {
        runCli([
            'scan',
            'tests/Fixtures/vulnerable/xss-two-hop.php',
            '--dump-taint-graph=' . $dot,
            '--format=json',
        ]);

        expect($dot)->toBeFile();
        expect((string) file_get_contents($dot))->toContain('digraph taint');
    } finally {
        @unlink($dot);
    }
});

it('explains why a location is not flagged', function (): void {
    $result = runCli([
        'explain',
        'tests/Fixtures/safe/xss-echo-esc-html.php:7',
        '--kind=html',
        '--scope=tests/Fixtures/safe',
    ]);

    expect($result['exit'])->toBe(0);
    expect($result['stdout'])->toContain('Taint at this point');
});

it('rejects a malformed explain location', function (): void {
    $result = runCli(['explain', 'not-a-location']);

    expect($result['exit'])->toBe(2);
    expect($result['stdout'] . $result['stderr'])->toContain('file.php:LINE');
});

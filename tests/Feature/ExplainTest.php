<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

/**
 * `explain` answers "why was this *not* flagged?"
 *
 * The failure mode a security scanner most needs to defend against is silence,
 * and silence is invisible by construction. This is the only part of the tool
 * that makes a false negative inspectable, so its three answers are pinned
 * here.
 */

/**
 * @return array{exit: int, output: string}
 */
function explainAt(string $file, int $line, ?string $kind = null, array $extra = []): array
{
    $arguments = ['php', 'bin/wp-taint', 'explain', $file . ':' . $line, '--scope=' . dirname($file), '--no-ansi'];

    if ($kind !== null) {
        $arguments[] = '--kind=' . $kind;
    }

    $process = new Process([...$arguments, ...$extra], projectRoot());
    $process->run();

    return ['exit' => $process->getExitCode() ?? -1, 'output' => $process->getOutput() . $process->getErrorOutput()];
}

function explainScratch(string $code): string
{
    $directory = sys_get_temp_dir() . '/wp-taint-explain-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);
    $path = $directory . '/a.php';
    file_put_contents($path, $code);

    return $path;
}

it('says a sanitizer cleared the taint', function (): void {
    $path = explainScratch(<<<'PHP'
        <?php
        $filter = $_GET['q'];
        $safe = esc_html($filter);
        echo $safe;
        PHP);

    try {
        $result = explainAt($path, 4, 'html');

        expect($result['exit'])->toBe(0);
        // esc_html() clears html and nothing else, so the other kinds remain —
        // which is the whole point of not modelling taint as a boolean.
        expect($result['output'])->toContain('No finding is expected here for kind=html');
        expect($result['output'])->toContain('esc_html() clears html');
        expect($result['output'])->toContain('Still carrying:');
    } finally {
        @unlink($path);
        @rmdir(dirname($path));
    }
});

it('says nothing tainted ever reached the location', function (): void {
    $path = explainScratch(<<<'PHP'
        <?php
        $greeting = 'hello';
        echo $greeting;
        PHP);

    try {
        $result = explainAt($path, 3, 'html');

        expect($result['exit'])->toBe(0);
        expect($result['output'])->toContain('Taint at this point: (none)');
        expect($result['output'])->toContain('No tainted value reaches this location');
    } finally {
        @unlink($path);
        @rmdir(dirname($path));
    }
});

it('names the path it abandoned at an unresolved dynamic call', function (): void {
    // The important one. It converts "I do not trust this tool" into a
    // specific, checkable statement about what the engine did and did not do.
    $path = explainScratch(<<<'PHP'
        <?php
        $callback = $_GET['mode'] === 'a' ? 'render_a' : 'render_b';
        $value = $callback($_GET['v']);
        echo $value;
        PHP);

    try {
        $result = explainAt($path, 4, 'html');

        expect($result['exit'])->toBe(0);
        expect($result['output'])->toContain('A potential path was abandoned');
        expect($result['output'])->toContain('could not be resolved');
        expect($result['output'])->toContain('KNOWN_LIMITATIONS.md');
        expect($result['output'])->toContain('--assume-dynamic-tainted');
    } finally {
        @unlink($path);
        @rmdir(dirname($path));
    }
});

it('confirms a finding is expected where one is', function (): void {
    $path = explainScratch(<<<'PHP'
        <?php
        $filter = $_GET['q'];
        echo $filter;
        PHP);

    try {
        $result = explainAt($path, 3, 'html');

        expect($result['output'])->toContain('A finding IS expected here for kind=html');
    } finally {
        @unlink($path);
        @rmdir(dirname($path));
    }
});

it('gives an upper bound on what it might be missing', function (): void {
    // Noisy by design: it is what you want when auditing the auditor.
    $directory = sys_get_temp_dir() . '/wp-taint-dynamic-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);
    file_put_contents($directory . '/a.php', <<<'PHP'
        <?php
        $callback = $_GET['mode'] === 'a' ? 'render_a' : 'render_b';
        echo $callback($_GET['v']);
        PHP);

    try {
        $quiet = new Process(
            ['php', 'bin/wp-taint', 'scan', $directory, '--format=json', '--fail-on=never', '--no-ansi', '--no-cache'],
            projectRoot(),
        );
        $quiet->run();

        $loud = new Process(
            [
                'php',
                'bin/wp-taint',
                'scan',
                $directory,
                '--format=json',
                '--fail-on=never',
                '--no-ansi',
                '--no-cache',
                '--assume-dynamic-tainted',
            ],
            projectRoot(),
        );
        $loud->run();

        $count = static fn (string $json): int => count(
            json_decode($json, true, 512, JSON_THROW_ON_ERROR)['findings'],
        );

        expect($count($quiet->getOutput()))->toBe(0);
        expect($count($loud->getOutput()))->toBe(1);

        // And the extra finding is marked, so it can be filtered back out.
        /** @var array{findings: list<array{imprecise: bool}>} $payload */
        $payload = json_decode($loud->getOutput(), true, 512, JSON_THROW_ON_ERROR);

        expect($payload['findings'][0]['imprecise'])->toBeTrue();
    } finally {
        @unlink($directory . '/a.php');
        @rmdir($directory);
    }
});

it('reports a location with nothing analysable on it', function (): void {
    $path = explainScratch("<?php\n\n// just a comment\n");

    try {
        $result = explainAt($path, 3, 'html');

        expect($result['output'])->toContain('No analysable operation was found');
    } finally {
        @unlink($path);
        @rmdir(dirname($path));
    }
});

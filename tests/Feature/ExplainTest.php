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
    //
    // The callback comes in as a parameter, which is where value resolution
    // genuinely runs out of road: a literal or a phi of literals would resolve.
    $path = explainScratch(<<<'PHP'
        <?php
        function acme_render($callback) {
            $value = $callback($_GET['v']);
            echo $value;
        }
        PHP);

    try {
        $result = explainAt($path, 4, 'html', ['--dynamic-calls=clean']);

        expect($result['exit'])->toBe(0);
        expect($result['output'])->toContain('A potential path was abandoned');
        expect($result['output'])->toContain('could not be resolved');
        expect($result['output'])->toContain('--dynamic-calls=clean');
        expect($result['output'])->toContain('KNOWN_LIMITATIONS.md');
        expect($result['output'])->toContain('--dynamic-calls=tainted');
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

it('lets the reader choose which way to be wrong about a dynamic call', function (): void {
    // Three answers, none of them correct, and the choice belongs to whoever
    // reads the output. `propagate` is the default because an unresolved callee
    // is nearly always project code, and project code transforms its arguments
    // rather than laundering them.
    $directory = sys_get_temp_dir() . '/wp-taint-dynamic-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);
    file_put_contents($directory . '/a.php', <<<'PHP'
        <?php
        function acme_render($callback) {
            echo $callback($_GET['v']);
        }
        PHP);

    $scan = static function (array $extra) use ($directory): array {
        $process = new Process(
            [
                'php', 'bin/wp-taint', 'scan', $directory,
                '--format=json', '--fail-on=never', '--no-ansi',
                ...$extra,
            ],
            projectRoot(),
        );
        $process->run();

        /** @var array{findings: list<array{imprecise: bool}>} $payload */
        $payload = json_decode($process->getOutput(), true, 512, JSON_THROW_ON_ERROR);

        return $payload['findings'];
    };

    try {
        expect($scan(['--dynamic-calls=clean']))->toHaveCount(0);

        // The default: the argument reaches the echo through the unknown callee.
        $default = $scan([]);
        expect($default)->toHaveCount(1);
        expect($default[0]['imprecise'])->toBeTrue();

        expect($scan(['--dynamic-calls=tainted']))->toHaveCount(1);

        // The flag this replaced still works, and still means `tainted`.
        expect($scan(['--assume-dynamic-tainted']))->toHaveCount(1);
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

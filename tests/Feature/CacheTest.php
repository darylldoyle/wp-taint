<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

/**
 * The result cache.
 *
 * Because analysis is whole-program, the only sound cache unit is the whole
 * scan: caching one file's findings would be wrong the moment a function it
 * calls changed elsewhere. The key therefore covers every input, and the tests
 * below are all about it invalidating when it should.
 *
 * A stale clean result from a security scanner is not a performance bug, it is
 * a lie.
 */

/**
 * @return array{findings: int, exit: int}
 */
function scanWithCache(string $directory, string $cacheDirectory): array
{
    $output = $directory . '/out.json';

    $process = new Process([
        'php',
        'bin/wp-taint',
        'scan',
        $directory,
        '--format=json',
        '--output=' . $output,
        '--fail-on=never',
        '--no-ansi',
        '--cache-dir=' . $cacheDirectory,
    ], projectRoot());

    $process->run();

    /** @var array{findings: list<mixed>} $decoded */
    $decoded = json_decode((string) file_get_contents($output), true, 512, JSON_THROW_ON_ERROR);

    return ['findings' => count($decoded['findings']), 'exit' => $process->getExitCode() ?? -1];
}

function makeScratchDirectory(): string
{
    $directory = sys_get_temp_dir() . '/wp-taint-cache-test-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);

    return $directory;
}

function removeScratchDirectory(string $directory): void
{
    foreach (glob($directory . '/*') ?: [] as $file) {
        @unlink($file);
    }

    @rmdir($directory);
}

it('serves an identical result from cache and invalidates on any change', function (): void {
    $source = makeScratchDirectory();
    $cache = makeScratchDirectory();

    try {
        file_put_contents($source . '/a.php', "<?php\necho esc_html(\$_GET['q']);\n");

        expect(scanWithCache($source, $cache)['findings'])->toBe(0, 'cold run');
        expect(scanWithCache($source, $cache)['findings'])->toBe(0, 'warm run');

        // A new file in the tree changes the key.
        file_put_contents($source . '/b.php', "<?php\necho \$_POST['unsafe'];\n");
        expect(scanWithCache($source, $cache)['findings'])->toBe(1, 'after adding a file');

        // So does editing an existing one.
        file_put_contents($source . '/a.php', "<?php\necho \$_GET['q'];\n");
        expect(scanWithCache($source, $cache)['findings'])->toBe(2, 'after editing a file');

        // And removing one.
        unlink($source . '/b.php');
        expect(scanWithCache($source, $cache)['findings'])->toBe(1, 'after removing a file');
    } finally {
        removeScratchDirectory($source);
        removeScratchDirectory($cache);
    }
});

it('produces byte-identical output cached and uncached', function (): void {
    $source = makeScratchDirectory();
    $cache = makeScratchDirectory();

    try {
        file_put_contents($source . '/a.php', <<<'PHP'
            <?php
            function acme_wrap($v) { return '<b>' . $v . '</b>'; }
            echo acme_wrap($_GET['q']);
            PHP);

        $strip = static function (string $path): string {
            /** @var array{scan: array<string, mixed>} $decoded */
            $decoded = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
            unset($decoded['scan']['durationMs'], $decoded['scan']['root']);

            return json_encode($decoded, JSON_THROW_ON_ERROR);
        };

        scanWithCache($source, $cache);
        $cached = $strip($source . '/out.json');

        $process = new Process([
            'php',
            'bin/wp-taint',
            'scan',
            $source,
            '--format=json',
            '--output=' . $source . '/out.json',
            '--fail-on=never',
            '--no-ansi',
            '--no-cache',
        ], projectRoot());
        $process->run();

        expect($strip($source . '/out.json'))->toBe($cached);
    } finally {
        removeScratchDirectory($source);
        removeScratchDirectory($cache);
    }
});

it('does not use the cache when --no-cache is passed', function (): void {
    $source = makeScratchDirectory();
    $cache = makeScratchDirectory();

    try {
        file_put_contents($source . '/a.php', "<?php\necho 'safe';\n");
        scanWithCache($source, $cache);

        expect(glob($cache . '/*.cache'))->toHaveCount(1);

        $process = new Process([
            'php',
            'bin/wp-taint',
            'scan',
            $source,
            '--no-cache',
            '--no-ansi',
            '--cache-dir=' . $cache,
        ], projectRoot());
        $process->run();

        // Still one entry: --no-cache neither reads nor writes.
        expect(glob($cache . '/*.cache'))->toHaveCount(1);
    } finally {
        removeScratchDirectory($source);
        removeScratchDirectory($cache);
    }
});

it('treats a corrupt cache entry as a miss rather than an error', function (): void {
    $source = makeScratchDirectory();
    $cache = makeScratchDirectory();

    try {
        file_put_contents($source . '/a.php', "<?php\necho \$_GET['q'];\n");
        expect(scanWithCache($source, $cache)['findings'])->toBe(1);

        foreach (glob($cache . '/*.cache') ?: [] as $entry) {
            file_put_contents($entry, 'not a serialised ScanResult');
        }

        expect(scanWithCache($source, $cache)['findings'])->toBe(1);
    } finally {
        removeScratchDirectory($source);
        removeScratchDirectory($cache);
    }
});

<?php

declare(strict_types=1);

use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Registry\RegistryLoader;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Scan\ScanResult;
use Enshrined\WpTaint\Taint\AnalysisOptions;

/**
 * The project root, resolved once.
 */
function projectRoot(): string
{
    return dirname(__DIR__);
}

function registryDirectory(): string
{
    return projectRoot() . '/registries';
}

function fixturePath(string $relative): string
{
    return projectRoot() . '/tests/Fixtures/' . ltrim($relative, '/');
}

/**
 * The resolved catalogue, cached per name because loading and validating it is
 * the slowest thing in the unit suite.
 */
function testRegistry(string $name = 'wordpress', bool $storedTaint = true, bool $storedWrites = false): Registry
{
    static $cache = [];

    $key = $name . '|' . ($storedTaint ? '1' : '0') . '|' . ($storedWrites ? '1' : '0');

    return $cache[$key] ??= (new RegistryLoader(registryDirectory()))
        ->load($name)
        ->configured($storedTaint, $storedWrites);
}

/**
 * Scan a single fixture in isolation.
 *
 * Isolation matters here: several fixtures deliberately declare helpers with
 * the same name (`render_heading()` appears in both the vulnerable and the safe
 * version of the one-hop case), which is exactly what you want when each file
 * is a self-contained reproduction and exactly what you do not want if they are
 * all analysed as one program.
 */
function scanFixture(string $relative, ?AnalysisOptions $options = null, ?Registry $registry = null): ScanResult
{
    $path = fixturePath($relative);
    $requested = fixtureOptions($path);

    $scanner = new Scanner(
        $registry ?? testRegistry('wordpress', true, in_array('stored-taint-writes', $requested, true)),
        $options ?? new AnalysisOptions(
            unknownProvenance: in_array('unknown-provenance', $requested, true),
        ),
        dirname($path),
    );

    return $scanner->scan([$path]);
}

/**
 * Flags a fixture asks for, declared in the file itself.
 *
 *     // wp-taint-options stored-taint-writes
 *
 * Rules behind a flag had no way to be tested: the harness ran with defaults,
 * so a fixture for `wp.stored.untrusted-write` reported nothing and its
 * annotation could never be satisfied. Declaring the flag next to the code it
 * applies to keeps the fixture self-describing, which is the same reason the
 * expectations come from annotations rather than from engine output.
 *
 * @return list<string>
 */
function fixtureOptions(string $path): array
{
    $contents = @file_get_contents($path);

    if (
        $contents === false
        || preg_match('/\/\/\s*wp-taint-options\s+([a-z,\- ]+)/', $contents, $matches) !== 1
    ) {
        return [];
    }

    return array_values(array_filter(array_map('trim', explode(',', $matches[1]))));
}

/**
 * Scan an inline snippet by writing it to a temporary file.
 *
 * @param string $code PHP source including the opening tag
 */
function scanCode(string $code, ?AnalysisOptions $options = null, ?Registry $registry = null): ScanResult
{
    $directory = sys_get_temp_dir() . '/wp-taint-tests-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);
    $path = $directory . '/snippet.php';
    file_put_contents($path, $code);

    try {
        return (new Scanner(
            $registry ?? testRegistry(),
            $options ?? new AnalysisOptions(),
            $directory,
        ))->scan([$path]);
    } finally {
        @unlink($path);
        @rmdir($directory);
    }
}

/**
 * @return list<string> `ruleId@line` for every finding, in report order
 */
function findingSignatures(ScanResult $result): array
{
    return array_map(
        static fn (object $finding): string => $finding->ruleId . '@' . $finding->line,
        $result->findings->all(),
    );
}

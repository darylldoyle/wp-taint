<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;
use Enshrined\WpTaint\Taint\ParameterKeyReads;
use Enshrined\WpTaint\Taint\UserFunctionTable;

// A callee that reads its parameter only through literal keys sees only those
// elements of the array it is handed. Handing it every element's taint put a
// stored option written under `value` into a description read from `desc`.

/**
 * @return array<int, list<array-key>> the keys `acme_f()` reads each parameter through
 */
function keysReadBy(string $body): array
{
    $path = sys_get_temp_dir() . '/wp-taint-keys-' . bin2hex(random_bytes(6)) . '.php';
    file_put_contents($path, "<?php\n" . $body);

    try {
        $parsed = (new CfgBuilder(dirname($path)))->buildFromFile($path)->file();
    } finally {
        unlink($path);
    }

    $functions = new UserFunctionTable();
    $functions->addFile($parsed);

    foreach ($parsed->script->functions as $func) {
        if (str_ends_with(strtolower($func->name), 'acme_f')) {
            return (new ParameterKeyReads($functions))->of($func);
        }
    }

    throw new RuntimeException('acme_f() was not declared.');
}

/**
 * @return list<string> rule@line for each finding
 */
function keyReadFindings(string $body): array
{
    $directory = sys_get_temp_dir() . '/wp-taint-key-reads-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);
    file_put_contents($directory . '/plugin.php', "<?php\n" . $body);

    try {
        $result = (new Scanner(testRegistry(), new AnalysisOptions(), $directory))
            ->scan((new FileFinder())->find([$directory]));
    } finally {
        unlink($directory . '/plugin.php');
        rmdir($directory);
    }

    return array_map(
        static fn ($finding): string => $finding->ruleId . '@' . $finding->line,
        $result->findings->all(),
    );
}

it('lists the literal keys a parameter is read through', function (): void {
    expect(keysReadBy(<<<'PHP'
        function acme_f( $field, $other ) {
            if ( ! isset( $field['tip'] ) || ! is_array( $field ) || count( $field ) === 0 ) {
                $field['tip'] = '';
            }
            $field[] = 'appended';
            list( 'a' => $a ) = $field;
            return array( 'd' => $field['desc'], 'o' => $other );
        }
        PHP))->toBe([0 => ['a', 'desc', 'tip']]);
});

it('reads a parameter whole when it is used any other way', function (string $use): void {
    expect(keysReadBy("function acme_f( \$field ) { \$x = \$field['a']; {$use}; }"))->toBe([]);
})->with([
    'passed on' => 'acme_g( $field )',
    'copied' => '$copy = $field',
    'returned' => 'return $field',
    'iterated' => 'foreach ( $field as $v ) { echo 1; }',
    'computed key' => 'echo $field[ $x ]',
    'captured' => '$c = function () use ( $field ) {}',
    'concatenated' => 'echo "x" . $field',
    'defaulted' => '$y = $field ?? array()',
]);

it('reads every parameter whole where the variables are read without their names', function (string $use): void {
    expect(keysReadBy("function acme_f( \$field, \$other ) { \$x = \$field['a'] . \$other['b']; {$use}; }"))
        ->toBe([]);
})->with([
    'func_get_args' => '$all = func_get_args()',
    'compact' => '$all = compact( "field" )',
    'get_defined_vars' => '$all = get_defined_vars()',
    'variable variable' => '$name = "field"; echo $$name',
    'arrow function' => '$f = fn() => $field',
    'include' => 'include "x.php"',
]);

it('reads a variadic parameter whole', function (): void {
    expect(keysReadBy('function acme_f( ...$fields ) { return $fields[0]; }'))->toBe([]);
});

it('does not take a namespace\'s own is_array() for PHP\'s', function (string $declared, array $keys): void {
    expect(keysReadBy(<<<PHP
        namespace Acme;
        {$declared}
        function acme_f( \$field ) { \$y = is_array( \$field ); return \$field['a']; }
        PHP))->toBe($keys);
})->with([
    'none declared' => ['', [0 => ['a']]],
    'its own' => ['function is_array( $x ) { return $x; }', []],
]);

it('keeps an element the callee does not read out of what it returns', function (): void {
    $findings = keyReadFindings(<<<'PHP'
        function acme_describe( $field ) {
            return array( 'tip' => $field['desc'] );
        }
        function acme_show() {
            $field = array( 'desc' => 'A description.' );
            $field['value'] = $_GET['value'];
            $parts = acme_describe( $field );
            echo $parts['tip'];
        }
        PHP);

    expect($findings)->toBe([]);
});

it('still hands the callee an element it reads', function (): void {
    expect(keyReadFindings(<<<'PHP'
        function acme_describe( $field ) {
            return array( 'tip' => $field['desc'] );
        }
        function acme_show() {
            $field = array();
            $field['desc'] = $_GET['desc'];
            $parts = acme_describe( $field );
            echo $parts['tip'];
        }
        PHP))->toContain('wp.xss.unescaped-output@9');
});

it('keeps an element the callee does not read out of its sinks', function (): void {
    $findings = keyReadFindings(<<<'PHP'
        function acme_render( $field ) {
            echo $field['desc'];
        }
        function acme_show() {
            $field = array( 'desc' => 'A description.' );
            $field['value'] = $_GET['value'];
            acme_render( $field );
        }
        PHP);

    expect($findings)->toBe([]);
});

it('still hands the callee the array\'s own taint and its computed-key elements', function (string $write): void {
    expect(keyReadFindings(<<<PHP
        function acme_render( \$field ) {
            echo \$field['desc'];
        }
        function acme_show( \$key ) {
            {$write}
            acme_render( \$field );
        }
        PHP))->toContain('wp.xss.unescaped-output@3');
})->with([
    'own' => '$field = $_GET["field"];',
    'computed key' => '$field = array(); $field[ $key ] = $_GET["value"];',
]);

it('hands the whole argument on where it does not go to one parameter', function (string $call): void {
    expect(keyReadFindings(<<<PHP
        function acme_render( \$field ) {
            echo \$field['desc'];
        }
        function acme_show() {
            // Under the parameter's name, which is what unpacking a string
            // key hands it.
            \$fields = array( 'field' => array( 'desc' => \$_GET['desc'] ) );
            {$call};
        }
        PHP))->toContain('wp.xss.unescaped-output@3');
})->with([
    'unpacked' => 'acme_render( ...$fields )',
    'call_user_func_array' => 'call_user_func_array( "acme_render", $fields )',
    'array_map' => 'array_map( "acme_render", $fields )',
    'array_walk' => 'array_walk( $fields, "acme_render" )',
]);

it('traces a returned element to the key the callee read', function (): void {
    $directory = sys_get_temp_dir() . '/wp-taint-key-trace-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);
    file_put_contents($directory . '/plugin.php', <<<'PHP'
        <?php
        function acme_describe( $field ) {
            return array( 'tip' => $field['desc'] );
        }
        function acme_show() {
            $field = array();
            $field['value'] = $_POST['value'];
            $field['desc'] = $_GET['desc'];
            $parts = acme_describe( $field );
            echo $parts['tip'];
        }
        PHP);

    try {
        $findings = (new Scanner(testRegistry(), new AnalysisOptions(), $directory))
            ->scan((new FileFinder())->find([$directory]))
            ->findings
            ->all();
    } finally {
        unlink($directory . '/plugin.php');
        rmdir($directory);
    }

    expect($findings)->toHaveCount(1);

    $lines = array_map(static fn ($step): int => $step->line, $findings[0]->trace);

    expect($lines)->toContain(8)->and($lines)->not->toContain(7);
});

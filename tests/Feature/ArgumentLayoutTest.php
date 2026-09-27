<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// php-cfg lists a call's arguments in the order they were written, and each
// went to the parameter at the same position. Unpacked arrays, named
// arguments, variadic parameters and the dispatchers that unpack an array all
// hand values to other parameters than that.

/**
 * @return list<string> rule@line for each finding
 */
function layoutFindings(string $body): array
{
    $directory = sys_get_temp_dir() . '/wp-taint-layout-' . bin2hex(random_bytes(6));
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

it('hands an unpacked array to every parameter from its position on', function (string $call): void {
    expect(layoutFindings(<<<PHP
        function acme_f( \$a, \$b ) {
            echo \$b;
        }
        function acme_run() {
            \$args = array( 'x', \$_GET['w'] );
            {$call};
        }
        PHP))->toContain('wp.xss.unescaped-output@3');
})->with([
    'unpacked' => 'acme_f( ...$args )',
    'through call_user_func' => 'call_user_func( "acme_f", ...$args )',
    'call_user_func_array' => 'call_user_func_array( "acme_f", $args )',
]);

it('hands a literal array\'s values to the parameters they name', function (): void {
    $findings = layoutFindings(<<<'PHP'
        function acme_f( $a, $b ) {
            echo $b;
        }
        function acme_g( $a, $b ) {
            echo $a;
        }
        function acme_run() {
            call_user_func_array( 'acme_f', array( $_GET['v'], 'x' ) );
            call_user_func_array( 'acme_g', array( 'b' => $_GET['v'], 'a' => 'x' ) );
        }
        PHP);

    expect($findings)->toBe([]);
});

it('hands a named argument to the parameter of that name', function (): void {
    $findings = layoutFindings(<<<'PHP'
        function acme_field( $label, $field ) {
            echo $field;
        }
        function acme_label( $label, $field ) {
            echo $label;
        }
        function acme_run() {
            acme_field( field: $_GET['x'], label: 'y' );
            acme_label( field: $_GET['x'], label: 'y' );
        }
        PHP);

    expect($findings)->toBe(['wp.xss.unescaped-output@3']);
});

it('collects every argument past a variadic parameter into it', function (): void {
    expect(layoutFindings(<<<'PHP'
        function acme_list( $first, ...$rest ) {
            echo $rest[1];
        }
        function acme_run() {
            acme_list( 'a', 'b', $_GET['x'] );
        }
        PHP))->toContain('wp.xss.unescaped-output@3');
});

it('hands a dispatcher\'s callback the values its catalogue entry lists', function (string $body, int $line): void {
    expect(layoutFindings($body))->toContain('wp.xss.unescaped-output@' . $line);
})->with([
    'array_walk extra argument' => [<<<'PHP'
        function acme_walk( $item, $key, $prefix ) {
            echo $prefix;
        }
        function acme_run( $items ) {
            array_walk( $items, 'acme_walk', $_GET['prefix'] );
        }
        PHP, 3],
    'array_reduce initial value' => [<<<'PHP'
        function acme_run() {
            array_reduce( array( 'a' ), function ( $carry, $item ) {
                echo $carry;
                return $carry;
            }, $_GET['start'] );
        }
        PHP, 4],
    'array_reduce items into the carry' => [<<<'PHP'
        function acme_run() {
            array_reduce( $_GET['items'], function ( $carry, $item ) {
                echo $carry;
                return $carry . $item;
            }, '' );
        }
        PHP, 4],
    'array_map second array' => [<<<'PHP'
        function acme_run() {
            array_map( function ( $a, $b ) {
                echo $b;
            }, array( 'x' ), $_GET['list'] );
        }
        PHP, 4],
]);

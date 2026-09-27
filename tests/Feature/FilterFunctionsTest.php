<?php

declare(strict_types=1);

// filter_var() returns a number for FILTER_VALIDATE_INT and the value as it
// was for FILTER_DEFAULT. What comes back depends on the filter constant, so
// the constant is read.

/**
 * @return list<string> rule@line for each finding
 */
function filterFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('clears a value a number filter admits, quoted or not', function (string $filter): void {
    expect(filterFindings(<<<PHP
        function acme_run() {
            global \$wpdb;
            \$id = filter_var( \$_GET['id'], {$filter} );
            \$wpdb->query( "DELETE FROM t WHERE id = \$id" );
            echo \$id;
        }
        PHP))->toBe([]);
})->with(['FILTER_VALIDATE_INT', 'FILTER_VALIDATE_FLOAT', 'FILTER_VALIDATE_BOOLEAN', 'FILTER_VALIDATE_BOOL']);

it('passes the value through a filter that proves nothing', function (string $call): void {
    expect(filterFindings(<<<PHP
        function acme_run( \$filter ) {
            echo {$call};
        }
        PHP))->toBe(['wp.xss.unescaped-output@3']);
})->with([
    'no filter' => ["filter_var( \$_GET['v'] )"],
    'FILTER_DEFAULT' => ["filter_var( \$_GET['v'], FILTER_DEFAULT )"],
    'FILTER_UNSAFE_RAW' => ["filter_var( \$_GET['v'], FILTER_UNSAFE_RAW )"],
    'FILTER_VALIDATE_EMAIL' => ["filter_var( \$_GET['v'], FILTER_VALIDATE_EMAIL )"],
    'FILTER_VALIDATE_URL' => ["filter_var( \$_GET['v'], FILTER_VALIDATE_URL )"],
    'FILTER_VALIDATE_DOMAIN' => ["filter_var( \$_GET['v'], FILTER_VALIDATE_DOMAIN )"],
    'a filter in a variable' => ["filter_var( \$_GET['v'], \$filter )"],
]);

it('credits an encoding filter for HTML and not for SQL', function (): void {
    expect(filterFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $v = filter_var( $_GET['v'], FILTER_SANITIZE_SPECIAL_CHARS );
            echo '<a title="' . $v . '">';
            $wpdb->query( "DELETE FROM t WHERE name = '$v'" );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@6']);
});

it('credits an address filter with its alphabet', function (): void {
    expect(filterFindings(<<<'PHP'
        function acme_run() {
            echo filter_var( $_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP );
        }
        PHP))->toBe([]);
});

it('carries the options raw, because options.default comes back unfiltered', function (): void {
    expect(filterFindings(<<<'PHP'
        function acme_run() {
            echo filter_var( $_GET['v'], FILTER_VALIDATE_INT, array( 'options' => array( 'default' => $_GET['d'] ) ) );
            echo filter_var( $_GET['v'], FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE );
        }
        PHP))->toBe(['wp.xss.unescaped-output@3']);
});

it('reads filter_input() as the request, filtered by its constant', function (): void {
    expect(filterFindings(<<<'PHP'
        function acme_run() {
            echo filter_input( INPUT_GET, 'v' );
            echo filter_input( INPUT_GET, 'n', FILTER_VALIDATE_INT );
            echo filter_input( INPUT_POST, 'name', FILTER_SANITIZE_FULL_SPECIAL_CHARS );
        }
        PHP))->toBe(['wp.xss.unescaped-output@3']);
});

it('does not read a definition array', function (): void {
    expect(filterFindings(<<<'PHP'
        function acme_run() {
            $data = filter_input_array( INPUT_POST, array( 'id' => FILTER_VALIDATE_INT ) );
            echo $data['id'];
            $all = filter_var_array( $_POST, FILTER_VALIDATE_INT );
            echo $all['id'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@4']);
});

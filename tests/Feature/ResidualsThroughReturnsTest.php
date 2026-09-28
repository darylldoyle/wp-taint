<?php

declare(strict_types=1);

// A helper's summary is built by seeding its parameter with `sql`. A caller's
// escaped value carries `sql_unquoted` or `sql_self_quoted` instead, which the
// record did not name, so it came back from any helper carrying no SQL kind at
// all: an escaped value passed through `function id( $v ) { return $v; }` and
// used unquoted was never reported.

/**
 * @return list<string> rule@line for each finding
 */
function residualReturnFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('hands an escaped value back escaped through a helper that returns it as it came', function (string $helper): void {
    expect(residualReturnFindings(<<<PHP
        function acme_helper( \$v ) {
            return {$helper};
        }
        function acme_run() {
            global \$wpdb;
            \$q = acme_helper( esc_sql( \$_GET['x'] ) );
            \$wpdb->query( "SELECT * FROM t WHERE a = \$q" );
            \$wpdb->query( "SELECT * FROM t WHERE a = '\$q'" );
        }
        PHP))->toBe(['wp.sqli.unprepared-query@8']);
})->with([
    'unchanged' => ['$v'],
    'trimmed' => ['trim( $v )'],
]);

it('hands an escaped value back raw through a helper that may undo the escaping', function (): void {
    expect(residualReturnFindings(<<<'PHP'
        function acme_inner( $v ) {
            return stripslashes( $v );
        }
        function acme_outer( $v ) {
            return acme_inner( $v );
        }
        function acme_run() {
            global $wpdb;
            $one = acme_inner( esc_sql( $_GET['x'] ) );
            $two = acme_outer( esc_sql( $_GET['y'] ) );
            $wpdb->query( "SELECT * FROM t WHERE a = '$one'" );
            $wpdb->query( "SELECT * FROM t WHERE a = '$two'" );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@12', 'wp.sqli.wpdb-query@13']);
});

it('hands a value that brings its own quotes back through a helper', function (): void {
    expect(residualReturnFindings(<<<'PHP'
        function acme_helper( $v ) {
            return $v;
        }
        function acme_run() {
            global $wpdb;
            $q = acme_helper( "'" . esc_sql( $_GET['x'] ) . "'" );
            $wpdb->query( "SELECT * FROM t WHERE a = $q" );
            $wpdb->query( "SELECT * FROM t WHERE a = '$q'" );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@9']);
});

it('hands an escaped element back raw from a helper that may undo the escaping', function (): void {
    expect(residualReturnFindings(<<<'PHP'
        function acme_wrap( $v ) {
            return array( 'raw' => stripslashes( $v ) );
        }
        function acme_run() {
            global $wpdb;
            $r = acme_wrap( esc_sql( $_GET['x'] ) );
            $wpdb->query( "SELECT * FROM t WHERE a = '{$r['raw']}'" );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@8']);
});

it('does not hand an escaped value back raw for a helper that unslashes other data', function (): void {
    // Yoast SEO's bulk editor: the helper that builds the query unslashes the
    // order it reads from the request, and returns the post-type clause it
    // was handed as it came.
    expect(residualReturnFindings(<<<'PHP'
        function acme_query( $clause ) {
            $order = sanitize_text_field( wp_unslash( $_GET['order'] ) );
            return "SELECT ID FROM t WHERE 1 = 1 $clause ORDER BY ID";
        }
        function acme_run() {
            global $wpdb;
            $clause = "AND post_type IN ('" . esc_sql( $_GET['type'] ) . "')";
            $wpdb->get_results( acme_query( $clause ) );
        }
        PHP))->toBe([]);
});

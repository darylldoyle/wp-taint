<?php

declare(strict_types=1);

// esc_sql() makes a value safe inside quotes and only there, and the quotes
// are usually added where the value is used. The sink saw only the finished
// query, so a clause built with its own quotes and joined into a query later
// read as unquoted, and a helper that escaped or quoted its argument lost the
// fact on the way back to its caller.

/**
 * @return list<string> rule@line for each finding
 */
function quoteContextFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('credits an escaped value inside quotes its own clause writes', function (): void {
    // WooCommerce's API keys list builds its search clause this way.
    expect(quoteContextFindings(<<<'PHP'
        function acme_run( $c ) {
            global $wpdb;
            $search = '';
            if ( $c ) {
                $search = "AND name LIKE '%" . esc_sql( $wpdb->esc_like( $_GET['s'] ) ) . "%' ";
            }
            $wpdb->get_results( "SELECT * FROM t WHERE 1 = 1 {$search}" );
        }
        PHP))->toBe([]);
});

it('reports a clause that brings its own quotes placed inside more', function (): void {
    expect(quoteContextFindings(<<<'PHP'
        function acme_run( $c ) {
            global $wpdb;
            $name = '';
            if ( $c ) {
                $name = "'" . esc_sql( $_GET['n'] ) . "'";
            }
            $wpdb->query( "SELECT * FROM t WHERE title = '$name'" );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@8']);
});

it('reads a literal sprintf() format as the quotes it writes', function (): void {
    expect(quoteContextFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $wpdb->query( sprintf( "DELETE FROM t WHERE name = '%s'", esc_sql( $_GET['n'] ) ) );
            $wpdb->query( sprintf( "DELETE FROM t WHERE id = %s", esc_sql( $_GET['id'] ) ) );
            $wpdb->query( sprintf( "DELETE FROM t WHERE id = %d", $_GET['id'] ) );
        }
        PHP))->toBe(['wp.sqli.unprepared-query@5']);
});

it('writes a format argument whole, elements and all', function (): void {
    // `implode()` hands back its elements' taint as a container. Reading only
    // the argument's own taint lost it, and Code Snippets' attribute list
    // with it.
    expect(quoteContextFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $attributes = array( 'data-line' => $_GET['line'] );
            echo sprintf( '<pre %s>', implode( ' ', $attributes ) );
            $wpdb->query( sprintf( 'DELETE FROM t WHERE id IN (%s)', implode( ',', $_GET['ids'] ) ) );
        }
        PHP))->toBe(['wp.xss.unescaped-output@5', 'wp.sqli.wpdb-query@6']);
});

it('quotes escaped elements joined between quotes, through a helper and a callee', function (): void {
    // Jetpack Sync's disallowed post types. The elements are a container, and
    // the clause is returned, extended and placed bare one call down.
    expect(quoteContextFindings(<<<'PHP'
        function acme_types_sql() {
            return "post_type NOT IN ('" . implode( "', '", array_map( 'esc_sql', get_option( 'acme_types' ) ) ) . "')";
        }
        function acme_odd_sql() {
            return "post_type NOT IN ('" . implode( "'", array_map( 'esc_sql', get_option( 'acme_types' ) ) ) . "')";
        }
        function acme_where() {
            return acme_types_sql() . ' AND ID > 0';
        }
        function acme_query( $where ) {
            global $wpdb;
            return $wpdb->get_col( "SELECT ID FROM t WHERE {$where}" );
        }
        function acme_run() {
            acme_query( acme_where() );
            acme_query( acme_odd_sql() );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@13']);
});

it('keeps elements quoted through an implode() glue that re-quotes them', function (): void {
    expect(quoteContextFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $ids = array_map( 'esc_sql', (array) $_POST['ids'] );
            $wpdb->query( "DELETE FROM t WHERE slug IN ('" . implode( "','", $ids ) . "')" );
            $wpdb->query( "DELETE FROM t WHERE slug IN ('" . implode( "'", $ids ) . "')" );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@6']);
});

it('turns an escaped value raw again through a function that can undo it', function (string $undo): void {
    expect(quoteContextFindings(<<<PHP
        function acme_run() {
            global \$wpdb;
            \$v = {$undo};
            \$wpdb->query( "DELETE FROM t WHERE name = '\$v'" );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@5']);
})->with([
    'rawurldecode' => ["rawurldecode( esc_sql( \$_GET['n'] ) )"],
    'stripslashes' => ["stripslashes( esc_sql( \$_GET['n'] ) )"],
    'trim with a mask' => ["trim( esc_sql( \$_GET['n'] ), '\\\\' )"],
]);

it('keeps an escaped value escaped through a function that cannot undo it', function (): void {
    expect(quoteContextFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $v = strtolower( trim( esc_sql( $_GET['n'] ) ) );
            $wpdb->query( "DELETE FROM t WHERE name = '$v'" );
        }
        PHP))->toBe([]);
});

it('hands a caller what a helper made of its argument', function (): void {
    expect(quoteContextFindings(<<<'PHP'
        function acme_escape( $v ) {
            return esc_sql( $v );
        }
        function acme_clause( $v ) {
            return sprintf( " AND name = '%s'", esc_sql( $v ) );
        }
        function acme_run() {
            global $wpdb;
            $wpdb->query( "DELETE FROM t WHERE id = " . acme_escape( $_GET['id'] ) );
            $wpdb->query( "DELETE FROM t WHERE name = '" . acme_escape( $_GET['n'] ) . "'" );
            $wpdb->query( "DELETE FROM t WHERE 1 = 1" . acme_clause( $_GET['n'] ) );
        }
        PHP))->toBe(['wp.sqli.unprepared-query@10']);
});

it('reports an escaped argument a callee puts where it is not safe', function (): void {
    $findings = quoteContextFindings(<<<'PHP'
        function acme_column( $col ) {
            global $wpdb;
            return $wpdb->get_results( "SELECT $col FROM t" );
        }
        function acme_named( $name ) {
            global $wpdb;
            return $wpdb->get_results( "SELECT * FROM t WHERE name = '$name'" );
        }
        function acme_run() {
            acme_column( esc_sql( $_GET['c'] ) );
            acme_named( esc_sql( $_GET['n'] ) );
            acme_named( "'" . esc_sql( $_GET['m'] ) . "'" );
        }
        PHP);

    expect(array_count_values($findings))->toBe([
        'wp.sqli.unprepared-query@4' => 2,
        'wp.sqli.unprepared-query@8' => 2,
    ]);
});

it('does not read a quote inside a backtick identifier as opening a string', function (): void {
    expect(quoteContextFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $wpdb->query( "SELECT `it's` FROM t WHERE id = " . esc_sql( $_GET['id'] ) );
        }
        PHP))->toBe(['wp.sqli.unprepared-query@4']);
});

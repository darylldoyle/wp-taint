<?php

declare(strict_types=1);

// A function that hands part of its parameter on to another function reads
// that part out of sight. Summarised with one part for the whole of it, the
// caller's stored values reached everything the part reached, the keys'
// uses included. These are the shapes behind two false WooCommerce findings
// that put stored order data in the column names of an INSERT.

/**
 * @return list<string> rule@line for each finding
 */
function handedOnPartsFindings(string $body): array
{
    return array_values(array_filter(
        findingSignatures(scanCode("<?php\n" . $body)),
        static fn (string $finding): bool => str_starts_with($finding, 'wp.sqli.wpdb-query@'),
    ));
}

it('keeps the values of an array a wrapper hands on away from its keys', function (): void {
    expect(handedOnPartsFindings(<<<'PHP'
        function acme_insert( $data ) {
            global $wpdb;
            $columns = implode( ', ', array_keys( $data ) );
            $sql     = $wpdb->prepare( "INSERT INTO t ( $columns ) VALUES ( %s )", array_values( $data ) );
            $wpdb->query( $sql );
        }
        function acme_persist( $update ) {
            acme_insert( $update['data'] );
        }
        function acme_save() {
            acme_persist( array( 'data' => array( 'total' => get_option( 'acme_total' ) ) ) );
        }
        PHP))->toBe([]);
});

it('still reports a key a wrapper hands on', function (): void {
    expect(handedOnPartsFindings(<<<'PHP'
        function acme_insert( $data ) {
            global $wpdb;
            $columns = implode( ', ', array_keys( $data ) );
            $sql     = $wpdb->prepare( "INSERT INTO t ( $columns ) VALUES ( %s )", array_values( $data ) );
            $wpdb->query( $sql );
        }
        function acme_persist( $update ) {
            acme_insert( $update['data'] );
        }
        function acme_save() {
            acme_persist( array( 'data' => array( $_GET['column'] => 1 ) ) );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@6']);
});

it('follows a by-reference loop value to the parts it reads', function (): void {
    expect(handedOnPartsFindings(<<<'PHP'
        function acme_limit( $rows ) {
            foreach ( $rows as $i => &$row ) {
                $row['format'] = array_intersect_key( $row['format'], array( 'total' => 1 ) );
            }
            return $rows;
        }
        function acme_save() {
            global $wpdb;
            $rows = array(
                array(
                    'table'  => 'wp_t',
                    'data'   => array( 'total' => get_option( 'acme_total' ) ),
                    'format' => array( 'total' => '%s' ),
                ),
            );
            foreach ( acme_limit( $rows ) as $row ) {
                $formats = implode( ', ', $row['format'] );
                $sql     = $wpdb->prepare(
                    "INSERT INTO {$row['table']} VALUES ( $formats )",
                    array_values( $row['data'] )
                );
                $wpdb->query( $sql );
            }
        }
        PHP))->toBe([]);
});

it('keeps a list item apart through two functions that return it unchanged', function (): void {
    expect(handedOnPartsFindings(<<<'PHP'
        function acme_inner( $y ) {
            return $y;
        }
        function acme_wrap( $x ) {
            return acme_inner( $x );
        }
        function acme_save() {
            global $wpdb;
            $rows   = array();
            $rows[] = array( 'table' => 'wp_t', 'data' => array( 'total' => get_option( 'acme_total' ) ) );
            foreach ( acme_wrap( $rows ) as $row ) {
                $sql = $wpdb->prepare( "INSERT INTO {$row['table']} VALUES ( %s )", array_values( $row['data'] ) );
                $wpdb->query( $sql );
            }
        }
        PHP))->toBe([]);
});

it('still reports a list item that two functions return unchanged', function (): void {
    expect(handedOnPartsFindings(<<<'PHP'
        function acme_inner( $y ) {
            return $y;
        }
        function acme_wrap( $x ) {
            return acme_inner( $x );
        }
        function acme_save() {
            global $wpdb;
            $rows   = array();
            $rows[] = array( 'table' => $_GET['table'], 'data' => array() );
            foreach ( acme_wrap( $rows ) as $row ) {
                $sql = $wpdb->prepare( "INSERT INTO {$row['table']} VALUES ( %s )", array_values( $row['data'] ) );
                $wpdb->query( $sql );
            }
        }
        PHP))->toBe(['wp.sqli.wpdb-query@14']);
});

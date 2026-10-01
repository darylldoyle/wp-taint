<?php

declare(strict_types=1);

// str_replace() with a search and a replacement that hold no quote, backtick
// or backslash cannot move an escaped value out of its quotes. WooCommerce's
// report queries rename a column in a clause with the protected
// str_replace_clause( 'where_time', 'date_created', 'timestamp' ).

/**
 * @return list<string> rule@line for each SQL injection finding
 */
function quoteFreeReplaceFindings(string $search, string $replace): array
{
    return array_values(array_filter(
        findingSignatures(scanCode("<?php\n" . <<<PHP
            class Acme_Query {
                private \$where = '';
                public function add( \$clause ) {
                    \$this->where .= \$clause;
                }
                protected function rename( \$search, \$replace ) {
                    \$this->where = str_replace( \$search, \$replace, \$this->where );
                }
                public function run() {
                    global \$wpdb;
                    return \$wpdb->get_results( 'SELECT id FROM t WHERE 1=1 ' . \$this->where );
                }
            }
            class Acme_Store extends Acme_Query {
                public function report() {
                    \$this->add( " AND status = '" . esc_sql( get_option( 'acme_status' ) ) . "'" );
                    \$this->rename( {$search}, {$replace} );
                    return \$this->run();
                }
            }
            PHP)),
        static fn (string $finding): bool => str_starts_with($finding, 'wp.sqli.wpdb-query@'),
    ));
}

it('keeps the escaping through a replacement with no quotes', function (): void {
    expect(quoteFreeReplaceFindings("'date_created'", "'timestamp'"))->toBe([]);
});

it('still reports a replacement that puts a quote in', function (): void {
    expect(quoteFreeReplaceFindings("'status'", "\"x' OR '\""))->toBe(['wp.sqli.wpdb-query@12']);
});

it('still reports a replacement it cannot read', function (): void {
    expect(quoteFreeReplaceFindings("'status'", "get_option( 'acme_column' )"))->toBe(['wp.sqli.wpdb-query@12']);
});

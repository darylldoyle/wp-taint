<?php

declare(strict_types=1);

// A glue built from a method that returns one of a few known strings keeps
// the quotes when every one of them does. WooCommerce's report stores join
// their clauses with implode( " {$operator} ", ... ), where
// get_match_operator() returns 'AND' or 'OR'.

/**
 * @return list<string> rule@line for each SQL injection finding
 */
function glueChoiceFindings(string $operators): array
{
    return array_values(array_filter(
        findingSignatures(scanCode("<?php\n" . <<<PHP
            class Acme_Store {
                protected function get_match_operator( \$args ) {
                    {$operators}
                }
                public function run( \$args ) {
                    global \$wpdb;
                    \$operator  = \$this->get_match_operator( \$args );
                    \$statuses  = array_map( 'esc_sql', (array) get_option( 'acme_statuses' ) );
                    \$clauses   = array();
                    \$clauses[] = "status NOT IN ( '" . implode( "','", \$statuses ) . "' )";
                    \$clauses[] = 'id > 0';
                    \$wpdb->query( 'SELECT id FROM t WHERE ' . implode( " {\$operator} ", \$clauses ) );
                }
            }
            PHP)),
        static fn (string $finding): bool => str_starts_with($finding, 'wp.sqli.wpdb-query@'),
    ));
}

it('keeps the quotes for a glue of a few known strings', function (): void {
    expect(glueChoiceFindings(
        "\$operator = 'AND'; if ( 'any' === \$args['match'] ) { \$operator = 'OR'; } return \$operator;"
    ))->toBe([]);
});

it('still reports a glue one of whose strings moves the quotes', function (): void {
    expect(glueChoiceFindings(
        "if ( 'any' === \$args['match'] ) { return \"' OR \"; } return 'AND';"
    ))->toBe(['wp.sqli.wpdb-query@13']);
});

it('still reports a glue that may be anything', function (): void {
    expect(glueChoiceFindings("return \$args['match'];"))->toBe(['wp.sqli.wpdb-query@13']);
});

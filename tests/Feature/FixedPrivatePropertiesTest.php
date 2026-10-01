<?php

declare(strict_types=1);

// A private property declared as a literal array that nothing writes holds
// its declaration wherever it is read. WooCommerce's SqlQuery reads the
// clause types a filtered clause is made of from one, so the where clause
// reads 'where' and 'where_time' and not every clause type.

/**
 * @return list<string> rule@line for each finding
 */
function fixedPropertyFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

/** The query class, with `$extra` added to its body. */
function fixedPropertyQuery(string $extra = ''): string
{
    return <<<PHP
        class Acme_Query {
            private \$clauses = array( 'where' => array(), 'where_time' => array(), 'order_by' => array() );
            private \$filters = array( 'where' => array( 'where', 'where_time' ) );
            public function add( \$type, \$clause ) {
                \$this->clauses[ \$type ][] = \$clause;
            }
            protected function filtered( \$type ) {
                \$clauses = array();
                foreach ( \$this->filters[ \$type ] as \$subset ) {
                    \$clauses = array_merge( \$clauses, \$this->clauses[ \$subset ] );
                }
                return implode( ' ', \$clauses );
            }
            public function where() {
                return 'SELECT id FROM t WHERE 1=1 ' . \$this->filtered( 'where' );
            }
            {$extra}
        }
        function acme_report() {
            global \$wpdb;
            \$query = new Acme_Query();
            \$query->add( 'order_by', \$_GET['orderby'] );
            \$wpdb->get_results( \$query->where() );
        }
        PHP;
}

it('reads the clause types a fixed private property lists', function (): void {
    expect(fixedPropertyFindings(fixedPropertyQuery()))->toBe([]);
});

it('does not trust a property the class writes', function (): void {
    // A write anywhere means the declaration may no longer be its value.
    expect(fixedPropertyFindings(fixedPropertyQuery(
        'public function widen() { $this->filters[\'where\'][] = \'order_by\'; }'
    )))->toBe(['wp.sqli.wpdb-query@24']);
});

it('does not trust a property name two classes declare', function (): void {
    // Either declaration alone would leave the where query clean. Two of them
    // under one name say nothing about which one a read sees.
    expect(fixedPropertyFindings(fixedPropertyQuery() . "\n" . <<<'PHP'
        class Acme_Other {
            private $filters = array( 'where' => array( 'where' ) );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@24']);
});

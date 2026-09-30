<?php

declare(strict_types=1);

// A call that passes a literal to a parameter the callee uses as an array key
// applies a summary of the callee with that parameter bound, so the callee
// reads and writes that key alone.

/**
 * @return list<string> rule@line for each finding
 */
function keyVariantFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('reads only the element a getter is asked for', function (): void {
    expect(keyVariantFindings(<<<'PHP'
        class Acme_Config {
            private $values;
            public function __construct() {
                $this->values = array( 'title' => $_GET['t'], 'mode' => 'grid' );
            }
            public function get( $key ) {
                return $this->values[ $key ];
            }
        }
        function acme_show() {
            $config = new Acme_Config();
            echo $config->get( 'mode' );
            echo $config->get( 'title' );
        }
        PHP))->toBe(['wp.xss.unescaped-output@14']);
});

it('picks only the element a helper is asked for out of its argument', function (): void {
    expect(keyVariantFindings(<<<'PHP'
        function acme_pick( $row, $field ) {
            return $row[ $field ];
        }
        function acme_show() {
            $row = array( 'raw' => $_GET['r'], 'label' => 'Name' );
            echo acme_pick( $row, 'label' );
            echo acme_pick( $row, 'raw' );
        }
        PHP))->toBe(['wp.xss.unescaped-output@8']);
});

it('passes a bound key on to the helper it calls', function (): void {
    expect(keyVariantFindings(<<<'PHP'
        function acme_inner( $row, $field ) {
            return $row[ $field ];
        }
        function acme_outer( $field ) {
            $row = array( 'raw' => $_GET['r'], 'label' => 'Name' );
            return acme_inner( $row, $field );
        }
        function acme_show() {
            echo acme_outer( 'label' );
            echo acme_outer( 'raw' );
        }
        PHP))->toBe(['wp.xss.unescaped-output@11']);
});

it('still reads any element for a key the caller cannot name', function (): void {
    expect(keyVariantFindings(<<<'PHP'
        function acme_pick( $row, $field ) {
            return $row[ $field ];
        }
        function acme_show( $which ) {
            $row = array( 'raw' => $_GET['r'], 'label' => 'Name' );
            echo acme_pick( $row, $which );
        }
        PHP))->toBe(['wp.xss.unescaped-output@7']);
});

// Past the cap a call applies the function's own summary, property writes
// included. The cap used to stay in the table the rounds merge into, so no
// call saw it and one past it waited for its variant for good.

it('writes a property through a call past the variant cap', function (): void {
    $keys = '';

    for ($i = 0; $i < 17; $i++) {
        $keys .= "    \$query->add( 'key{$i}', 'x' );\n";
    }

    expect(keyVariantFindings(<<<PHP
        class Acme_Query {
            private \$clauses = array( 'limit' => array() );
            public function add( \$type, \$clause ) {
                \$this->clauses[ \$type ][] = \$clause;
            }
            public function statement() {
                return 'SELECT * FROM t ' . implode( ' ', \$this->clauses['limit'] );
            }
        }
        function acme_many_keys( Acme_Query \$query ) {
        {$keys}
        }
        function acme_limited( Acme_Query \$query ) {
            global \$wpdb;
            \$query->add( 'limit', 'LIMIT ' . \$_GET['n'] );
            return \$wpdb->get_results( \$query->statement() );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@34']);
});

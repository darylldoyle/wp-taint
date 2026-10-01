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
// call saw it and one past it waited for its variant for good. The hook name
// hands the key on, so add() has the cap of 16 and not the higher one.

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
                do_action( \$type );
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
        PHP))->toBe(['wp.sqli.wpdb-query@35']);
});

// A getter and a setter that use their key only to pick an element may have
// 256 variants, not 16. WooCommerce's WC_Data::get_prop() is called with 183
// prop names. The keys here sort after the first 16, so a cap of 16 would
// leave them to the shared summary.

/**
 * A data class with 20 props and getters for two of them. It stores
 * 'zz_count' through absint() and 'zz_name' raw. `$extra` goes into both
 * accessors, and it is the only thing each test changes.
 */
function pickingDataClass(string $extra): string
{
    $props = '';
    $loads = '';

    for ($i = 0; $i < 18; $i++) {
        $props .= "'key{$i}' => '', ";
        $loads .= "        \$this->set_prop( 'key{$i}', absint( get_post_meta( 1, 'key{$i}', true ) ) );\n";
    }

    return <<<PHP
        class Acme_Data {
            protected \$data = array( {$props}'zz_count' => 0, 'zz_name' => '' );
            protected function set_prop( \$prop, \$value ) {
                if ( array_key_exists( \$prop, \$this->data ) && \$value !== \$this->data[ \$prop ] ) {
                    \$this->data[ \$prop ] = \$value;
                }
                {$extra}
            }
            protected function get_prop( \$prop ) {
                {$extra}
                return apply_filters( 'acme_get_' . \$prop, \$this->data[ \$prop ] );
            }
            public function load() {
        {$loads}
                \$this->set_prop( 'zz_count', absint( get_post_meta( 1, 'zz_count', true ) ) );
                \$this->set_prop( 'zz_name', get_post_meta( 1, 'zz_name', true ) );
            }
            public function count() {
                return \$this->get_prop( 'zz_count' );
            }
            public function name() {
                return \$this->get_prop( 'zz_name' );
            }
        }
        function acme_show() {
            \$data = new Acme_Data();
            \$data->load();
            echo \$data->count();
            echo \$data->name();
        }
        PHP;
}

it('reads one element through a getter called with more than 16 keys', function (): void {
    $findings = keyVariantFindings(pickingDataClass(''));

    expect($findings)->toBe(['wp.xss.unescaped-output@48']);
});

it('keeps the cap of 16 for an accessor that hands its key on', function (): void {
    $findings = keyVariantFindings(pickingDataClass('do_action( $prop );'));

    expect($findings)->toBe(['wp.xss.unescaped-output@47', 'wp.xss.unescaped-output@48']);
});

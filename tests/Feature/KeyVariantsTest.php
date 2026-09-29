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

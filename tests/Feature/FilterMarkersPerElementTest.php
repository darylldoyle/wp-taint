<?php

declare(strict_types=1);

// A filter voids the escaping of what it returns. An array it hands back
// keeps each element's own `escaped`, so an element nobody escaped is left to
// the other rules, and one that was escaped is still reported as voided.

/**
 * @return list<string> rule@line for each finding
 */
function filterMarkerFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('voids only the element that was escaped', function (): void {
    expect(filterMarkerFindings(<<<'PHP'
        function acme_render() {
            $data = apply_filters( 'acme_receipt', array(
                'amount'    => esc_html( get_option( 'acme_amount' ) ),
                'constants' => array( 'font_size' => 12 ),
                'title'     => __( 'Receipt', 'acme' ),
            ) );
            echo $data['amount'];
            echo $data['constants']['font_size'];
            echo $data['title'];
        }
        PHP))->toBe(['wp.xss.escape-voided@8']);
});

it('keeps a nested element\'s marker under its own keys', function (): void {
    expect(filterMarkerFindings(<<<'PHP'
        function acme_render() {
            $data = apply_filters( 'acme_data', array(
                'a' => array( 'b' => esc_html( get_option( 'acme_b' ) ) ),
                'c' => array( 'd' => 'x' ),
            ) );
            echo $data['a']['b'];
            echo $data['c']['d'];
        }
        PHP))->toBe(['wp.xss.escape-voided@7']);
});

it('still voids the escaped element when the array is printed whole or looped over', function (): void {
    expect(filterMarkerFindings(<<<'PHP'
        function acme_render() {
            $data = apply_filters( 'acme_data', array( 'a' => esc_html( get_option( 'acme_a' ) ), 'n' => 12 ) );
            echo implode( ',', $data );
            foreach ( $data as $value ) {
                echo $value;
            }
        }
        PHP))->toBe(['wp.xss.escape-voided@4', 'wp.xss.escape-voided@6']);
});

it('still voids an escaped value handed to the filter beside the array', function (): void {
    // A callback can return any argument it is given.
    expect(filterMarkerFindings(<<<'PHP'
        function acme_render() {
            $extra = array( 'a' => esc_html( get_option( 'acme_a' ) ) );
            $data  = apply_filters( 'acme_data', array( 'n' => 12 ), $extra );
            echo $data['n'];
        }
        PHP))->toBe(['wp.xss.escape-voided@5']);
});

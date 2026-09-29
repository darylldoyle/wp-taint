<?php

declare(strict_types=1);

// A helper's return keeps the markers its argument carried, as a property, a
// capture and an included file's scope already do: `escaped` and
// `escape_voided` ride with HTML, and unknown origin rides when the body
// clears nothing.

/**
 * @return list<string> rule@line for each finding
 */
function returnMarkerFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('keeps an escaped and filtered value escape-voided through a helper that returns it', function (): void {
    expect(returnMarkerFindings(<<<'PHP'
        function acme_id( $v ) {
            return $v;
        }
        function acme_show() {
            echo acme_id( apply_filters( 'acme', esc_html( $_GET['t'] ) ) );
        }
        PHP))->toBe(['wp.xss.escape-voided@6']);
});

it('keeps a value of unknown origin unknown through a helper that returns it', function (): void {
    // A helper that sanitises settles it, as a sanitiser in the caller would.
    expect(returnMarkerFindings(<<<'PHP'
        function acme_id( $v ) {
            return $v;
        }
        function acme_clean( $v ) {
            return sanitize_text_field( $v );
        }
        function acme_render( $block ) {
            echo acme_id( $block );
            echo acme_clean( $block );
        }
        PHP))->toBe(['wp.output.unescaped-unknown@9']);
});

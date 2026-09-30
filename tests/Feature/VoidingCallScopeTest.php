<?php

declare(strict_types=1);

// A call that runs a filter voids the escaping of its own result, and of
// nothing else. The escaped marker it adds comes from its own arguments.

/**
 * @return list<string> rule@line for each finding
 */
function voidingScopeFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('voids no value an op after the call writes', function (): void {
    // The isset() check behind `??` ran on the second pass while the
    // do_shortcode() call from the end of the function was still the call
    // that voided, and it took that call's escaped argument.
    expect(voidingScopeFindings(<<<'PHP'
        function acme_render( $settings ) {
            $image = $settings['image'] ?? array();
            echo wp_get_attachment_image( $image['id'], 'medium' );
            $gallery = do_shortcode( '[gallery ids="' . esc_attr( get_option( 'acme_ids' ) ) . '"]' );
        }
        function acme_render_printed() {
            echo do_shortcode( '[gallery ids="' . esc_attr( get_option( 'acme_ids' ) ) . '"]' );
        }
        PHP))->toBe(['wp.xss.escape-voided@8']);
});

it('takes the escaped marker only from an argument escaped as a whole', function (): void {
    // Elementor reads an attachment id out of a widget's settings. Other
    // fields of the settings were escaped and filtered, so the read carries
    // their marker beside the stored html.
    expect(voidingScopeFindings(<<<'PHP'
        function acme_settings() {
            $settings = get_post_meta( 5, '_acme_settings', true );
            foreach ( (array) get_option( 'acme_controls' ) as $name ) {
                $settings[ $name ] = apply_filters( 'acme_tag', esc_html( $settings[ $name ] ) );
            }
            return $settings;
        }
        function acme_render() {
            $settings = acme_settings();
            echo wp_get_attachment_image( $settings['image']['id'], 'medium' );
            echo wp_trim_words( esc_html( $settings['title'] ), 20 );
            echo do_shortcode( '[gallery ids="' . esc_attr( $settings['ids'] ) . '"]' );
            echo $settings['caption'];
        }
        PHP))->toBe([
        'wp.xss.escape-voided@12',
        'wp.xss.escape-voided@13',
        'wp.xss.escape-voided@14',
    ]);
});

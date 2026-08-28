<?php

$fixture_f16_message = '';
add_action( 'init', function () use ( &$fixture_f16_message ) {
    if ( isset( $_POST['message'] ) ) {
        // @wp-taint-source F16
        $fixture_f16_message = sanitize_text_field( wp_unslash( $_POST['message'] ) );
    }
} );
add_action( 'fixture_f16_render', function () use ( &$fixture_f16_message ) {
    // @wp-taint-sink F16 expect=clean
    echo '<aside>' . esc_html( $fixture_f16_message ) . '</aside>';
} );

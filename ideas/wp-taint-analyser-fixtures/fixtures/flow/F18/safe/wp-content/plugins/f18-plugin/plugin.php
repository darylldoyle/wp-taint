<?php

function fixture_f18_script() {
    // @wp-taint-source F18
    $message = isset( $_GET['message'] ) ? sanitize_text_field( wp_unslash( $_GET['message'] ) ) : '';
    $script = 'window.fixtureMessage = ' . wp_json_encode( $message, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT ) . ';';
    // @wp-taint-sink F18 expect=clean
    wp_add_inline_script( 'fixture-app', $script, 'before' );
}

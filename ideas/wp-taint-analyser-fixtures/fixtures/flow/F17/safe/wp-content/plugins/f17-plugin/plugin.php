<?php

function fixture_f17_render_remote() {
    $response = wp_remote_get( 'https://example.invalid/card' );
    if ( is_wp_error( $response ) ) { return; }
    // @wp-taint-source F17
    $html = wp_remote_retrieve_body( $response );
    $html = apply_filters( 'fixture_f17_remote_html', $html );
    // @wp-taint-sink F17 expect=clean
    echo wp_kses_post( $html );
}

<?php

function fixture_i08_refresh() {
    $response = wp_remote_get( 'https://example.invalid/feed' );
    if ( is_wp_error( $response ) ) { return; }
    // @wp-taint-source I08
    $body = wp_remote_retrieve_body( $response );
    $body = wp_kses_post( $body );
    // @wp-taint-sink I08 expect=clean
    update_option( 'fixture_i08_remote_html', $body );
}

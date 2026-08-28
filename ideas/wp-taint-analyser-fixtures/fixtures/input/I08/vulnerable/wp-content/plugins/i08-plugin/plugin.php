<?php

function fixture_i08_refresh() {
    $response = wp_remote_get( 'https://example.invalid/feed' );
    if ( is_wp_error( $response ) ) { return; }
    // @wp-taint-source I08
    $body = wp_remote_retrieve_body( $response );
    // @wp-taint-sink I08 expect=input.unsanitized_storage
    update_option( 'fixture_i08_remote_html', $body );
}

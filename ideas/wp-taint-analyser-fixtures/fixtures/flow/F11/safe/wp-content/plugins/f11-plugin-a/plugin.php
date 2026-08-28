<?php

add_filter( 'fixture_f11_heading', function ( $heading ) {
    if ( ! isset( $_GET['heading'] ) ) { return $heading; }
    // @wp-taint-source F11
    return sanitize_text_field( wp_unslash( $_GET['heading'] ) );
} );

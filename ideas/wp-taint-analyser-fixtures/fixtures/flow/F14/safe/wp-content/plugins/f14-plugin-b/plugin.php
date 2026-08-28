<?php

add_filter( 'fixture_f14_banner', function ( $banner ) {
    if ( ! isset( $_GET['suffix'] ) ) { return $banner; }
    // @wp-taint-source F14
    return $banner . sanitize_text_field( wp_unslash( $_GET['suffix'] ) );
} );

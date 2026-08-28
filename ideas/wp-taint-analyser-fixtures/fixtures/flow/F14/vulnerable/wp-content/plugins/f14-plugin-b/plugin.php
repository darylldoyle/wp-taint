<?php

add_filter( 'fixture_f14_banner', function ( $banner ) {
    if ( ! isset( $_GET['suffix'] ) ) { return $banner; }
    // @wp-taint-source F14
    return $banner . wp_unslash( $_GET['suffix'] );
} );

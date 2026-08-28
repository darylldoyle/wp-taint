<?php

function fixture_i07_remember_variant() {
    if ( ! isset( $_COOKIE['fixture_variant'] ) ) { return; }
    // @wp-taint-source I07
    $variant = sanitize_key( wp_unslash( $_COOKIE['fixture_variant'] ) );
    // @wp-taint-sink I07 expect=clean
    update_option( 'fixture_i07_variant', $variant );
}

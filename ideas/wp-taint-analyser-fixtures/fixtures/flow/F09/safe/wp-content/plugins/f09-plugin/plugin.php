<?php

function fixture_f09_render() {
    $name = 'Anonymous';
    if ( isset( $_GET['name'] ) ) {
        // @wp-taint-source F09
        $name = sanitize_text_field( wp_unslash( $_GET['name'] ) );
    }
    // @wp-taint-sink F09 expect=clean
    echo '<p>Hello ' . esc_html( $name ) . '</p>';
}

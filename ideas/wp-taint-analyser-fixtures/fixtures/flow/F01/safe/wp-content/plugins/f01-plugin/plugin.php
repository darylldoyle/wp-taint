<?php

function fixture_f01_render() {
    // @wp-taint-source F01
    $query = isset( $_GET['q'] ) ? sanitize_text_field( wp_unslash( $_GET['q'] ) ) : '';
    $label = trim( $query );
    // @wp-taint-sink F01 expect=clean
    echo '<p>' . esc_html( $label ) . '</p>';
}

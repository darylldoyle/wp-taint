<?php

function fixture_f10_render() {
    // @wp-taint-source F10
    $label = isset( $_GET['label'] ) ? sanitize_text_field( wp_unslash( $_GET['label'] ) ) : '';
    // @wp-taint-sink F10 expect=clean
    printf( '<span class="tag">%s</span>', esc_html( $label ) );
}

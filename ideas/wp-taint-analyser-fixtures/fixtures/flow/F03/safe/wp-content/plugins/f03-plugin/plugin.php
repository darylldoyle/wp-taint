<?php

function fixture_f03_shortcode( $atts, $content = '' ) {
    // @wp-taint-source F03
    $atts = shortcode_atts( array( 'class' => 'fixture' ), $atts, 'fixture_f03' );
    $class = sanitize_html_class( $atts['class'] );
    // @wp-taint-sink F03 expect=clean
    return '<div class="' . esc_attr( $class ) . '">' . esc_html( $content ) . '</div>';
}

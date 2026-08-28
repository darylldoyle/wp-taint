<?php

function fixture_f03_shortcode( $atts, $content = '' ) {
    // @wp-taint-source F03
    $atts = shortcode_atts( array( 'class' => 'fixture' ), $atts, 'fixture_f03' );
    // @wp-taint-sink F03 expect=flow.unsanitized_unescaped
    return '<div class="' . $atts['class'] . '">' . esc_html( $content ) . '</div>';
}

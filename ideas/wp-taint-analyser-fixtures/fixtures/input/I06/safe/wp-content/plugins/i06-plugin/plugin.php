<?php

function fixture_i06_shortcode( $atts ) {
    // @wp-taint-source I06
    $atts = shortcode_atts( array( 'class' => 'default' ), $atts, 'fixture_i06' );
    $class = sanitize_html_class( $atts['class'] );
    // @wp-taint-sink I06 expect=clean
    update_post_meta( get_the_ID(), 'fixture_i06_class', $class );
    return '';
}

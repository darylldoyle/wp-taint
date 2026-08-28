<?php

// @wp-taint-source O10
$title = get_option( 'fixture_o10_title', '' );
$title = apply_filters( 'fixture_o10_title', $title );
// @wp-taint-sink O10 expect=clean
echo esc_html( $title );

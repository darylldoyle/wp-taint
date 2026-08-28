<?php

// @wp-taint-source O01
$title = get_option( 'fixture_o01_title', '' );
// @wp-taint-sink O01 expect=clean
echo '<h2>' . esc_html( $title ) . '</h2>';

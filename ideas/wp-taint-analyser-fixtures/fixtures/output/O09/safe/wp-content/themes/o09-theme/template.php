<?php

// @wp-taint-source O09
$url = get_option( 'fixture_o09_url', '' );
// @wp-taint-sink O09 expect=clean
echo '<a href="' . esc_url( $url ) . '">Fixture</a>';

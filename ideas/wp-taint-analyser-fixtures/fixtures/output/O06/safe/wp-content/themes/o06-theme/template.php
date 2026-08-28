<?php

// @wp-taint-source O06
$value = get_option( 'fixture_o06_js_value', '' );
// @wp-taint-sink O06 expect=clean
echo "<script>window.fixtureValue = '" . esc_js( $value ) . "';</script>";

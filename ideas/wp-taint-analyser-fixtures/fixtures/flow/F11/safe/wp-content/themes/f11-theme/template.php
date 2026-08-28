<?php

$heading = apply_filters( 'fixture_f11_heading', 'Welcome' );
// @wp-taint-sink F11 expect=clean
echo '<h1>' . esc_html( $heading ) . '</h1>';

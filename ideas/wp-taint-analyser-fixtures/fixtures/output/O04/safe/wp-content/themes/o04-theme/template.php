<?php

// @wp-taint-source O04
$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
$url = add_query_arg( 'fixture', '1', $request_uri );
// @wp-taint-sink O04 expect=clean
echo '<a href="' . esc_url( $url ) . '">Continue</a>';

<?php

// @wp-taint-source O09
$url = get_option( 'fixture_o09_url', '' );
// @wp-taint-sink O09 expect=output.wrong_context_escape
echo '<a href="' . esc_html( $url ) . '">Fixture</a>';

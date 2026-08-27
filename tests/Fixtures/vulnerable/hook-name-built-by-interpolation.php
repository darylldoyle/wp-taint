<?php
/**
 * Hook names are routinely built rather than written. The value resolver
 * follows the interpolation, so the registration lands on the same hook the
 * dispatch names.
 */

$acme_screen = 'render';

add_filter( "acme_{$acme_screen}_output", 'acme_raw_output' );

function acme_raw_output( $value ) {
	return $_GET['x'];
}

function acme_show_output() {
	echo apply_filters( 'acme_render_output', '' ); // wp-taint-expect wp.xss.unescaped-output html
}

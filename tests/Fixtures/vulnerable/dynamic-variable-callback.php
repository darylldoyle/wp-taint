<?php
/**
 * A callback variable holding one of two names reaches both, so a sink in
 * either is reported. Picking one would be a guess.
 */
function acme_render_escaped( $value ) {
	echo esc_html( $value );
}

function acme_render_plain( $value ) {
	echo $value; // wp-taint-expect wp.xss.unescaped-output html
}

function acme_dispatch( $mode ) {
	$callback = 'safe' === $mode ? 'acme_render_escaped' : 'acme_render_plain';

	$callback( $_GET['body'] );
}

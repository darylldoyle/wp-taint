<?php
/**
 * The pattern has to be a literal. A computed one proves nothing, and the call
 * goes back to being the propagator it always was.
 */

function acme_render( $pattern ) {
	$value = preg_replace( $pattern, '', $_GET['value'] );

	echo $value; // wp-taint-expect wp.xss.unescaped-output html
}

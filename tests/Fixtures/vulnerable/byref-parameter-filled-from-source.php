<?php
/**
 * The out-parameter is filled from a source inside the callee, so it carries
 * taint no argument supplied. The plan's canonical example.
 */

function acme_collect( array &$out ) {
	$out[] = $_GET['x'];
}

function acme_render() {
	$values = array();

	acme_collect( $values );

	echo $values[0]; // wp-taint-expect wp.xss.unescaped-output html
}

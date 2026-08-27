<?php
/**
 * Taint moved sideways: in through one parameter, out through another, without
 * ever being returned.
 */

function acme_append( $value, array &$out ) {
	$out[] = $value;
}

function acme_render() {
	$values = array();

	acme_append( $_POST['name'], $values );

	echo $values[0]; // wp-taint-expect wp.xss.unescaped-output html
}

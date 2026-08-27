<?php
/**
 * A literal pattern that is not a negated character class says nothing about
 * what survives it.
 */

function acme_render() {
	$value = preg_replace( '/<script>/', '', $_GET['value'] );

	echo $value; // wp-taint-expect wp.xss.unescaped-output html
}

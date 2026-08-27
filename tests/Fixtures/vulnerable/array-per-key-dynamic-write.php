<?php
/**
 * A computed key can land anywhere, so it goes to the whole-array slot and any
 * read has to see it. That is the behaviour every element write had before
 * per-key tracking, and it is still the fallback.
 */

function acme_render_context( $key ) {
	$context = array();

	$context[ $key ] = $_GET['value'];
	$context['id']   = 42;

	echo $context['id']; // wp-taint-expect wp.xss.unescaped-output html
}

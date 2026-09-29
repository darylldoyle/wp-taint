<?php
/**
 * A computed key can land anywhere, so it goes to the whole-array slot and any
 * read has to see it. That is the behaviour every element write had before
 * per-key tracking, and it is still the fallback.
 *
 * The computed write comes after the literal one. Before it, `$context['id']
 * = 42` would replace whatever it put under `'id'`.
 */

function acme_render_context( $key ) {
	$context = array();

	$context['id']   = 42;
	$context[ $key ] = $_GET['value'];

	echo $context['id']; // wp-taint-expect wp.xss.unescaped-output html
}

<?php
/**
 * And a computed read has to see every key, for the same reason.
 */

function acme_render_context( $key ) {
	$context = array();

	$context['title'] = $_GET['title'];
	$context['id']    = 42;

	echo $context[ $key ]; // wp-taint-expect wp.xss.unescaped-output html
}

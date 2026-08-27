<?php
/**
 * The other half. Reading the key that was tainted still reports.
 */

function acme_render_context() {
	$context = array();

	$context['title'] = $_GET['title'];
	$context['id']    = 42;

	echo $context['title']; // wp-taint-expect wp.xss.unescaped-output html
}

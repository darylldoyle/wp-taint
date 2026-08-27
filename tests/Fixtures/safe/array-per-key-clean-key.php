<?php
/**
 * Element taint is tracked per key when both the write and the read name a
 * constant one. Reading a key nothing tainted is not a finding.
 */

function acme_render_context() {
	$context = array();

	$context['title'] = $_GET['title'];
	$context['id']    = 42;

	echo $context['id'];
}

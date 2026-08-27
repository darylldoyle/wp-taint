<?php
/**
 * `$a = &$b` binds rather than copies. A later write through either name has to
 * be visible through the other, which SSA has no way to express: it versions
 * assignments, not aliases.
 */

function acme_collect() {
	$values = array();
	$sink   = &$values;

	$sink[] = $_GET['x'];

	echo $values[0]; // wp-taint-expect wp.xss.unescaped-output html
}

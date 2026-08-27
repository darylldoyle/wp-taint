<?php
/**
 * preg_match() returns a count; the interesting output goes out by reference.
 * SSA does not give that write its own operand, so the argument the caller
 * passed in is the slot it lands in.
 */

function acme_render_id() {
	preg_match( '/id-(\d+)/', $_GET['ref'], $matches );

	echo $matches[1]; // wp-taint-expect wp.xss.unescaped-output html
}

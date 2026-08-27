<?php
/**
 * By value, the same write changes nothing outside the loop.
 */

function acme_rewrite() {
	$items = array( 'a', 'b' );

	foreach ( $items as $item ) {
		$item = $_GET['replacement'];
	}

	echo $items[0];
}

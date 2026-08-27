<?php
/**
 * Writing through a by-reference loop variable writes into the collection.
 *
 * php-cfg lowers this to an AssignRef binding $item to the iterator's value,
 * and the `$item = …` inside the loop is a *fresh* SSA version — so the link
 * has to cover every version of the name, not just the one the binding
 * mentions.
 */

function acme_rewrite() {
	$items = array( 'a', 'b' );

	foreach ( $items as &$item ) {
		$item = $_GET['replacement'];
	}

	unset( $item );

	echo $items[0]; // wp-taint-expect wp.xss.unescaped-output html
}

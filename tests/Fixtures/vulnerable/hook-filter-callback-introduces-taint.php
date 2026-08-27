<?php
/**
 * A filter callback that reads request data taints the filter's result, even
 * when the value handed to apply_filters() was a literal. Invisible until the
 * hook graph existed.
 */

add_filter( 'acme_title', 'acme_inject_title' );

function acme_inject_title( $value ) {
	return $_GET['title'];
}

function acme_render_title() {
	echo apply_filters( 'acme_title', 'A safe default' ); // wp-taint-expect wp.xss.unescaped-output html
}

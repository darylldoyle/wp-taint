<?php
/**
 * A filter callback that escapes is not credited with escaping the value.
 *
 * This fixture used to sit under safe/. The scan cannot know which callbacks
 * are on `acme_title` when the filter fires. The registration can sit behind a
 * condition, `remove_filter()` can take it off, and code outside the scan can
 * add or remove callbacks. With nothing on the hook, apply_filters() returns
 * `$_GET['title']` unchanged, so the value handed in always reaches the result.
 */

add_filter( 'acme_title', 'acme_escape_title' );

function acme_escape_title( $value ) {
	return esc_html( $value );
}

function acme_render_title() {
	echo apply_filters( 'acme_title', $_GET['title'] ); // wp-taint-expect wp.xss.unescaped-output html
}

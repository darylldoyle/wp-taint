<?php
/**
 * The other half: a filter callback that escapes clears the taint the value
 * arrived with. Following hooks is only an improvement if it can prove a flow
 * safe as well as unsafe.
 */

add_filter( 'acme_title', 'acme_escape_title' );

function acme_escape_title( $value ) {
	return esc_html( $value );
}

function acme_render_title() {
	echo apply_filters( 'acme_title', $_GET['title'] );
}

<?php
/**
 * array_map() with a named escaper is a real sanitizer application, not an
 * opaque propagator.
 */
function acme_render_list() {
	$values = array_map( 'esc_html', $_GET['items'] );

	echo implode( ', ', $values );
}

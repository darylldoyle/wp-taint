<?php
/**
 * The callee escapes before writing back, so the caller receives clean data.
 */

function acme_collect_escaped( array &$out ) {
	$out[] = esc_html( $_GET['x'] );
}

function acme_render() {
	$values = array();

	acme_collect_escaped( $values );

	echo $values[0];
}

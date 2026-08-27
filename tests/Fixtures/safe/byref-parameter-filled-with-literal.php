<?php
/**
 * An out-parameter is only as tainted as what went into it.
 */

function acme_defaults( array &$out ) {
	$out[] = 'default';
}

function acme_render() {
	$values = array();

	acme_defaults( $values );

	echo $values[0];
}

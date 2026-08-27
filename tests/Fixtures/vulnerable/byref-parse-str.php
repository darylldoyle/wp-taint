<?php
/**
 * The highest-value case in the section: a real WordPress idiom that takes
 * attacker-controlled input by definition, and a silent false negative until
 * by-reference effects existed.
 */

function acme_redirect_from_query() {
	parse_str( $_SERVER['QUERY_STRING'], $args );

	wp_redirect( $args['next'] ); // wp-taint-expect wp.redirect.open-redirect url
}

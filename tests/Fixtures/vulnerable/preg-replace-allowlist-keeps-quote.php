<?php
/**
 * Per kind, never wholesale. This class keeps a hyphen, which the query's own
 * whitespace can turn into a comment, so the value is safe inside quotes only.
 * ORDER BY is not inside quotes. HTML taint is cleared.
 */

function acme_query() {
	global $wpdb;

	$order = preg_replace( '/[^a-zA-Z0-9_-]/', '', $_GET['orderby'] );

	$wpdb->get_results( 'SELECT * FROM things ORDER BY ' . $order ); // wp-taint-expect wp.sqli.unprepared-query sql
}

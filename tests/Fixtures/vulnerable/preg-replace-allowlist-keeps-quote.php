<?php
/**
 * Per kind, never wholesale. This class keeps a hyphen, which starts a SQL
 * comment, so SQL taint survives even though HTML does not.
 */

function acme_query() {
	global $wpdb;

	$order = preg_replace( '/[^a-zA-Z0-9_-]/', '', $_GET['orderby'] );

	$wpdb->get_results( 'SELECT * FROM things ORDER BY ' . $order ); // wp-taint-expect wp.sqli.wpdb-query sql
}

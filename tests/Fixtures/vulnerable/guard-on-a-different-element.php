<?php
/**
 * The check is on one key and the value copied is another, so nothing
 * constrains what reaches the query.
 */

function acme_log_query( array $params ) {
	$query = array( 'orderby' => 'id' );

	if ( isset( $params['orderby'] ) && in_array( $params['orderby'], array( 'ip', 'url' ), true ) ) {
		$query['orderby'] = $params['order_by'];
	}

	global $wpdb;

	return $wpdb->get_results( 'SELECT * FROM log ORDER BY ' . $query['orderby'] ); // wp-taint-expect wp.sqli.wpdb-query sql
}

acme_log_query( $_GET );

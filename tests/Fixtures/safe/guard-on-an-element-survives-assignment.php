<?php
/**
 * Redirection's log filter. Each parameter is checked against a list and only
 * then copied into the query parts, so the query is built from listed values.
 * The check is on an array element, and on a normalised copy of one.
 */

function acme_log_query( array $params ) {
	$query = array(
		'orderby'   => 'id',
		'direction' => 'DESC',
	);

	if ( isset( $params['orderby'] ) && in_array( $params['orderby'], array( 'ip', 'url' ), true ) ) {
		$query['orderby'] = $params['orderby'];
	}

	if ( isset( $params['direction'] ) && in_array( strtoupper( $params['direction'] ), array( 'ASC', 'DESC' ), true ) ) {
		$query['direction'] = strtoupper( $params['direction'] );
	}

	global $wpdb;

	return $wpdb->get_results( 'SELECT * FROM log ORDER BY ' . $query['orderby'] . ' ' . $query['direction'] );
}

acme_log_query( $_GET );

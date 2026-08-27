<?php
/**
 * call_user_func_array() spreads an array over the callee's parameters. The
 * array is one SSA operand, so its element taint feeds them all.
 */
function acme_query( $where ) {
	global $wpdb;

	$wpdb->get_results( 'SELECT * FROM things WHERE ' . $where ); // wp-taint-expect wp.sqli.wpdb-query sql
}

function acme_dispatch() {
	$args = array( $_GET['where'] );

	call_user_func_array( 'acme_query', $args );
}

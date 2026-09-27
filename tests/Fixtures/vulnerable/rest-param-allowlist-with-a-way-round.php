<?php
/**
 * The permission callback checks objectType against a list, but an editor is
 * let through before the check, so the table name the callback builds can be
 * anything that editor sends.
 */

add_action( 'rest_api_init', function () {
	register_rest_route( 'acme/v1', '/schemas', array(
		'methods'             => 'POST',
		'callback'            => 'acme_update_schemas',
		'permission_callback' => 'acme_schema_permissions',
	) );
} );

function acme_schema_permissions( $request ) {
	if ( current_user_can( 'edit_others_posts' ) ) {
		return true;
	}

	$type = $request->get_param( 'objectType' );

	if ( in_array( $type, array( 'post', 'term', 'user' ), true ) ) {
		return current_user_can( 'edit_posts' );
	}

	return false;
}

function acme_update_schemas( $request ) {
	global $wpdb;

	$type = $request->get_param( 'objectType' );

	return $wpdb->get_results( "SELECT meta_id FROM {$wpdb->prefix}{$type}meta" ); // wp-taint-expect wp.sqli.wpdb-query sql
}

<?php
/**
 * The permission callback lets a request through only when objectType is one
 * of three literals, one helper down, so the table name the callback builds is
 * one of three names. Rank Math's schema routes are written this way.
 */

add_action( 'rest_api_init', function () {
	register_rest_route( 'acme/v1', '/schemas', array(
		'methods'             => 'POST',
		'callback'            => 'acme_update_schemas',
		'permission_callback' => 'acme_schema_permissions',
	) );
} );

function acme_schema_permissions( $request ) {
	if ( ! current_user_can( 'edit_posts' ) ) {
		return new WP_Error( 'rest_forbidden', 'Not allowed.' );
	}

	return acme_object_permissions( $request );
}

function acme_object_permissions( $request ) {
	$type = $request->get_param( 'objectType' );

	if ( in_array( $type, array( 'post', 'term', 'user' ), true ) ) {
		return current_user_can( 'edit_posts' );
	}

	return false;
}

function acme_update_schemas( $request ) {
	global $wpdb;

	$type = $request->get_param( 'objectType' );

	return $wpdb->get_results( "SELECT meta_id FROM {$wpdb->prefix}{$type}meta" );
}

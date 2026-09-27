<?php

/**
 * The only capability check below this handler sits in a callback on a filter
 * that the handler's helper applies. The check decides what the filter does to
 * the record and guards nothing in the handler. The callback also runs only
 * while it is registered, which the scan cannot know.
 */

add_action( 'wp_ajax_nopriv_acme_lookup', 'acme_ajax_lookup' ); // wp-taint-expect wp.authz.ajax-missing-check authz

add_filter( 'acme_record', 'acme_strip_restricted' );

function acme_strip_restricted( $record ) {
	if ( is_super_admin() ) {
		return $record;
	}

	unset( $record['restricted'] );

	return $record;
}

function acme_load_record( $id ) {
	return apply_filters( 'acme_record', get_option( 'acme_record_' . absint( $id ) ) );
}

function acme_ajax_lookup() {
	wp_send_json( acme_load_record( $_POST['id'] ) );
}

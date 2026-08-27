<?php
/**
 * A helper whose name reads like a check but which checks nothing.
 *
 * The name heuristic this replaced accepted any call containing "verify", so
 * this was silent. Walking the call graph asks what the helper actually calls.
 */

add_action( 'wp_ajax_acme_save_prefs', 'acme_save_prefs' ); // wp-taint-expect wp.authz.ajax-missing-check authz

function acme_verify_request() {
	return true;
}

function acme_save_prefs() {
	if ( ! acme_verify_request() ) {
		wp_send_json_error( null, 403 );
	}

	update_option( 'acme_prefs', $_POST['prefs'] );
}

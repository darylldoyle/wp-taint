<?php
/**
 * The capability check sits three calls below the handler. Advanced Custom
 * Fields is why this matters: every one of its nopriv handlers delegates its
 * check to a helper, and reporting them all is how a tool gets muted.
 */

add_action( 'wp_ajax_acme_save_prefs', 'acme_save_prefs' );

function acme_gate() {
	return acme_gate_inner();
}

function acme_gate_inner() {
	return acme_capability_check();
}

function acme_capability_check() {
	return current_user_can( 'manage_options' );
}

function acme_save_prefs() {
	if ( ! acme_gate() ) {
		wp_send_json_error( null, 403 );
	}

	update_option( 'acme_prefs', $_POST['prefs'] );
}

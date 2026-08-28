<?php
/**
 * Fixture: code that *looks* like cleaning but does not neutralise the taint.
 * These probe whether the analyser has an allowlist of real sanitisers rather
 * than treating any transformation as cleansing.
 */

function fx_save_lookalikes() {
	// trim() removes whitespace only — payload survives.
	// ruleid: wp.input.weak-sanitiser
	update_option( 'fx_name', trim( $_POST['name'] ) );

	// stripslashes() un-escapes; it adds nothing.
	// ruleid: wp.input.weak-sanitiser
	update_option( 'fx_label', stripslashes( $_POST['label'] ) );

	// strtolower() preserves <script> payloads.
	// ruleid: wp.input.weak-sanitiser
	update_option( 'fx_code', strtolower( $_GET['code'] ) );

	// A nonce check proves intent, not cleanliness of the value.
	if ( wp_verify_nonce( $_POST['_fx_nonce'] ?? '', 'fx_save' ) ) {
		// ruleid: wp.input.unsanitised
		update_option( 'fx_after_nonce', $_POST['payload'] );
	}

	// Capability checks authorise the actor, not the data.
	if ( current_user_can( 'manage_options' ) ) {
		// ruleid: wp.input.unsanitised
		update_option( 'fx_admin_value', $_POST['admin_value'] );
	}

	// Validation without rejection: the boolean is checked, the raw value is kept.
	$maybe_email = wp_unslash( $_POST['contact'] );
	if ( ! is_email( $maybe_email ) ) {
		fx_log( 'invalid email supplied' );
	}
	// ruleid: wp.input.unsanitised
	update_option( 'fx_contact', $maybe_email );

	// substr() truncates but a short payload fits in 50 chars.
	// ruleid: wp.input.weak-sanitiser
	update_option( 'fx_excerpt', substr( $_POST['excerpt'], 0, 50 ) );
}

function fx_log( $msg ) {}

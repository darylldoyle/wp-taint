<?php
/**
 * Fixture: raw superglobals and WP request accessors persisted without sanitisation.
 * Every annotated line is VULNERABLE (CWE-20 improper input validation feeding
 * stored-XSS / injection potential downstream).
 */

function fx_save_raw() {
	// ruleid: wp.input.unsanitised
	update_option( 'fx_title', $_POST['title'] );

	// ruleid: wp.input.unsanitised
	update_option( 'fx_ref', $_GET['ref'] );

	// ruleid: wp.input.unsanitised
	update_option( 'fx_any', $_REQUEST['any'] );

	// ruleid: wp.input.unsanitised
	update_option( 'fx_track', $_COOKIE['fx_track'] );

	// ruleid: wp.input.unsanitised
	update_option( 'fx_ua', $_SERVER['HTTP_USER_AGENT'] );

	// ruleid: wp.input.unsanitised
	update_option( 'fx_uri', $_SERVER['REQUEST_URI'] );

	// ruleid: wp.input.unsanitised
	update_post_meta( 42, '_fx_note', wp_unslash( $_POST['note'] ) ); // unslash is not sanitisation

	$body = file_get_contents( 'php://input' );
	// ruleid: wp.input.unsanitised
	update_option( 'fx_webhook_payload', $body );

	// ruleid: wp.input.unsanitised
	update_user_meta( get_current_user_id(), 'fx_pref', get_query_var( 'fx_pref' ) );
}

<?php

/**
 * The correct idiom, and the one the rule used to report.
 *
 * Omit the nonce and `isset()` is false, so the conjunction is false, so
 * nothing is saved. "Check the nonce if one was supplied" is only a way in when
 * it guards the *denial*; here it guards the action.
 *
 * Seven plugins in the corpus write this and were told their CSRF check did not
 * work. The second function is the same thing inside a negation, which is how
 * Jetpack's disconnect handler spells it.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_save(): void {
	if ( isset( $_POST['_wpnonce'] ) && wp_verify_nonce( $_POST['_wpnonce'], 'acme' ) ) {
		update_option( 'acme_setting', 1 );
	}
}

function acme_disconnect(): void {
	if ( ! ( isset( $_GET['nonce'] ) && wp_verify_nonce( $_GET['nonce'], 'acme' ) ) ) {
		wp_die( 'Invalid nonce.' );
	}

	update_option( 'acme_connected', 0 );
}

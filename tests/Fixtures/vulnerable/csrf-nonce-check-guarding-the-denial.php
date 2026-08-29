<?php

/**
 * The same conjunction guarding `wp_die()` instead of the save. Send no nonce
 * and the guard is false, so the request is never stopped.
 *
 * This is the shape in the WordPress plugin team's intentionally vulnerable
 * plugin, and `false === wp_verify_nonce()` is the same denial spelled out.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_settings(): void {
	$nonce = 'acme_settings';

	if ( isset( $_REQUEST['nonce'] ) && ! wp_verify_nonce( $_REQUEST['nonce'], $nonce ) ) { // wp-taint-expect wp.csrf.bypassable-nonce-check authz
		wp_die( 'Invalid nonce.' );
	}

	update_option( 'acme_settings', wp_unslash( $_REQUEST['value'] ) );
}

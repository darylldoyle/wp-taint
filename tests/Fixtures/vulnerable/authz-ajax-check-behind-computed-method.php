<?php

/**
 * The handler on the second class checks nothing. What this fixture pins is
 * the *first* class staying quiet: its check is reached through a computed
 * method name that folds to exactly one string, and before the resolver asked
 * the value resolver about that, the call was unresolvable and the checked
 * handler was reported alongside the unchecked one.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

class Acme_Checked_Ajax {
	public function __construct() {
		add_action( 'wp_ajax_acme_checked', array( $this, 'handle' ) );
	}

	public function handle(): void {
		$method = 'verify';
		$this->$method();
		update_option( 'acme_checked', 1 );
	}

	private function verify(): void {
		check_ajax_referer( 'acme' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die();
		}
	}
}

class Acme_Unchecked_Ajax {
	public function __construct() {
		add_action( 'wp_ajax_acme_unchecked', array( $this, 'handle' ) ); // wp-taint-expect wp.authz.ajax-missing-check authz
	}

	public function handle(): void {
		update_option( 'acme_unchecked', 1 );
	}
}

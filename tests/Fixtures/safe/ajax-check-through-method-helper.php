<?php
/**
 * The same, through a method rather than a function.
 */

class Acme_Ajax {

	public function register() {
		add_action( 'wp_ajax_acme_reset', array( $this, 'handle' ) );
	}

	public function handle() {
		if ( ! $this->allowed() ) {
			wp_send_json_error( null, 403 );
		}

		delete_option( 'acme_state' );
	}

	private function allowed() {
		return current_user_can( 'manage_options' );
	}
}

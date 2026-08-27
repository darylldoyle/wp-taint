<?php
/**
 * The callback delegates its check to a helper, and the options arrive through
 * a variable. Both halves have to work for this to stay silent.
 */

class Acme_Rest_Routes {

	public function register() {
		$args = array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'save' ),
			'permission_callback' => array( $this, 'permit' ),
		);

		register_rest_route( 'acme/v1', '/save', $args );
	}

	public function permit() {
		return $this->gate();
	}

	private function gate() {
		return current_user_can( 'manage_options' );
	}

	public function save( $request ) {
		update_option( 'acme_thing', $request->get_param( 'value' ) );
	}
}

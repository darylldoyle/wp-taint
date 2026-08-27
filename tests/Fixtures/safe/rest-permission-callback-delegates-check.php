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

/**
 * The same delegation written as a one-liner, which is how SG AI Studio writes
 * it: no branch, no comparison, just a call. Thirty-seven findings on that
 * plugin until a callback that delegates counted as one we cannot judge.
 */
class Acme_Rest_Jwt_Routes {

	public function register() {
		register_rest_route(
			'acme/v1',
			'/jwt',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'save' ),
				'permission_callback' => array( $this, 'permit' ),
			)
		);
	}

	public function permit( $request ) {
		return $this->check_bearer_token( $request );
	}

	private function check_bearer_token( $request ) {
		$header = $request->get_header( 'Authorization' );

		return ! empty( $header ) && str_starts_with( $header, 'Bearer ' );
	}

	public function save( $request ) {
		update_option( 'acme_jwt', $request->get_param( 'value' ) );
	}
}

<?php
/**
 * Route options handed in from a method rather than written inline. This shape
 * was counted as unresolved and skipped, so the most safety-critical rule in
 * the tool quietly declined to look at it.
 */

class Acme_Rest_Routes {

	public function register() {
		register_rest_route( 'acme/v1', '/save', $this->route_args() ); // wp-taint-expect wp.authz.rest-public-write authz
	}

	public function route_args() {
		return array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'save' ),
			'permission_callback' => '__return_true',
		);
	}

	public function save( $request ) {
		update_option( 'acme_thing', $request->get_param( 'value' ) );
	}
}

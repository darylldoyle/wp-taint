<?php
/**
 * A permission callback that is present and does nothing.
 *
 * Presence used to be the whole test, which credited this exactly as much as a
 * real capability check. Reported at medium rather than critical: a callback
 * can be doing something legitimate the engine cannot see.
 */

class Acme_Rest_Routes {

	public function register() {
		register_rest_route( // wp-taint-expect wp.authz.rest-permission-callback-no-check authz
			'acme/v1',
			'/save',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'save' ),
				'permission_callback' => array( $this, 'permit' ),
			)
		);
	}

	public function permit() {
		return true;
	}

	public function save( $request ) {
		update_option( 'acme_thing', $request->get_param( 'value' ) );
	}
}

<?php

/**
 * A remote HTTP response is somebody else's output. The endpoint may be one the
 * plugin chose; the bytes that came back are not.
 *
 * It carries the stored kinds rather than the request ones, because the problem
 * is the same second-order shape an option has: something outside the plugin
 * decides what the value is, and the plugin prints or stores it.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_render_remote_card(): void {
	$response = wp_remote_get( 'https://example.invalid/card' );

	if ( is_wp_error( $response ) ) {
		return;
	}

	echo wp_remote_retrieve_body( $response ); // wp-taint-expect wp.xss.unescaped-output html
}

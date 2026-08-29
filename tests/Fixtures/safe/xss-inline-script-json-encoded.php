<?php

/**
 * JSON encoding is what makes a value safe in a JavaScript context, and it is
 * what the finding on the vulnerable twin asks for.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_inline_message_safely(): void {
	$message = isset( $_GET['message'] ) ? wp_unslash( $_GET['message'] ) : '';

	wp_add_inline_script( 'acme-app', 'window.acmeMessage = ' . wp_json_encode( $message ) . ';', 'before' );
}

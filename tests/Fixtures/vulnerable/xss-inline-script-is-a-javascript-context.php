<?php

/**
 * `wp_add_inline_script()` prints its argument inside a `<script>` block, so it
 * is a JavaScript context and no HTML escaper protects it. A single quote in
 * the value closes the string literal and the rest is code.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_inline_message(): void {
	$message = isset( $_GET['message'] ) ? wp_unslash( $_GET['message'] ) : '';

	wp_add_inline_script( 'acme-app', "window.acmeMessage = '" . $message . "';", 'before' ); // wp-taint-expect wp.xss.unescaped-output html
}

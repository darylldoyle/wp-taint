<?php

/**
 * A closure captures request data through its `use` clause and echoes it on a
 * hook. The body is a separate function with its own context, and the captured
 * variable arrives inside it as a free operand with nothing flowing in, so
 * until captures were published nothing connected the two.
 *
 * This is the shape WordPress plugins write constantly.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_register_notice(): void {
	$raw = isset( $_GET['msg'] ) ? $_GET['msg'] : '';

	add_action(
		'admin_notices',
		static function () use ( $raw ): void {
			echo '<div class="notice">' . $raw . '</div>'; // wp-taint-expect wp.xss.unescaped-output html
		}
	);
}

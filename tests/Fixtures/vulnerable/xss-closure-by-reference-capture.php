<?php

/**
 * `use ( &$x )` is a two-way binding and only one way was modelled. The first
 * closure's write never left it, so the second captured an empty string and the
 * echo read as clean.
 *
 * Round by round: the writing closure publishes what it assigned, the enclosing
 * scope picks it up, and the reading closure receives it through the ordinary
 * by-value capture on the round after that.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_register_notice(): void {
	$message = '';

	add_action(
		'init',
		static function () use ( &$message ): void {
			$message = isset( $_POST['message'] ) ? wp_unslash( $_POST['message'] ) : '';
		}
	);

	add_action(
		'admin_notices',
		static function () use ( &$message ): void {
			echo '<aside>' . $message . '</aside>'; // wp-taint-expect wp.xss.unescaped-output html
		}
	);
}

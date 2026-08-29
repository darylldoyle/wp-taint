<?php

/**
 * `use ( $x )` copies. A write inside the closure is invisible outside it,
 * which is the whole difference from `use ( &$x )`, so the second closure here
 * captures the empty string the first one was given rather than what it
 * assigned.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_register_notice_by_value(): void {
	$message = '';

	add_action(
		'init',
		static function () use ( $message ): void {
			$message = isset( $_POST['message'] ) ? wp_unslash( $_POST['message'] ) : '';
			unset( $message );
		}
	);

	add_action(
		'admin_notices',
		static function () use ( $message ): void {
			echo '<aside>' . $message . '</aside>';
		}
	);
}

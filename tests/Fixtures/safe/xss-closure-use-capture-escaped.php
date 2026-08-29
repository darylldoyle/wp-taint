<?php

/**
 * The same capture, escaped inside the closure. Publishing what a closure
 * captured has to keep this silent, or it trades one blind spot for noise on
 * every correctly written hook in WordPress.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_register_notice_safely(): void {
	$raw = isset( $_GET['msg'] ) ? $_GET['msg'] : '';

	add_action(
		'admin_notices',
		static function () use ( $raw ): void {
			echo '<div class="notice">' . esc_html( $raw ) . '</div>';
		}
	);
}

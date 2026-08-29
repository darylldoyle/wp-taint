<?php

/**
 * A user callback that reaches no catalogue sanitiser is accepted, because
 * absence proves nothing there: this allowlist reaches no sanitiser and is
 * exactly right.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_register_choice(): void {
	register_setting(
		'acme_group',
		'acme_mode',
		array( 'sanitize_callback' => __NAMESPACE__ . '\\acme_sanitize_mode' )
	);
}

function acme_sanitize_mode( $value ): string {
	return 'enabled' === $value ? 'enabled' : 'disabled';
}

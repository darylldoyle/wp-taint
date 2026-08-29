<?php

/**
 * The same deferral finding the callback clean. An allowlist returns one of its
 * own literals, never the posted value, so Storage does not survive it — which
 * is what makes it exactly the right sanitize_callback, with no catalogue
 * sanitizer anywhere in its body.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_register_mode(): void {
	register_setting( 'acme_group', 'acme_mode', array( 'sanitize_callback' => __NAMESPACE__ . '\\acme_mode_choice' ) );
}

function acme_mode_choice( $value ): string {
	return 'enabled' === $value ? 'enabled' : 'disabled';
}

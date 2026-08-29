<?php

/**
 * A user-defined sanitize_callback judged by its own body. The rule runs before
 * summaries exist, so the finding is deferred and adjudicated after the taint
 * pass: Storage survives from this callback's parameter to its return — every
 * sanitizer clears that kind and no propagator does — so it cleans nothing.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_register_trimmed(): void {
	register_setting( 'acme_group', 'acme_headline', array( 'sanitize_callback' => __NAMESPACE__ . '\\acme_tidy' ) ); // wp-taint-expect wp.input.setting-without-sanitize authz
}

function acme_tidy( $value ) {
	return trim( (string) $value );
}

<?php

/**
 * Naming a pass-through as the cleaner is the same as naming none.
 *
 * `wp_unslash()` undoes magic quotes and cleans nothing — the same catalogue
 * fact that stops it passing for a sanitiser in dataflow says why it cannot be
 * a `sanitize_callback` either.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_register_settings_badly(): void {
	register_setting( 'acme_group', 'acme_headline', array( 'sanitize_callback' => 'wp_unslash' ) ); // wp-taint-expect wp.input.setting-without-sanitize authz
}

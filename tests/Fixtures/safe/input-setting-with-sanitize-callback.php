<?php

/**
 * A `sanitize_callback` is present, so core cleans the value before storing it.
 *
 * The pre-4.7 signature passed a callable as the third argument instead. A
 * plugin still using it has named something to clean the value, so a non-array
 * third argument is accepted rather than reported.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_register_settings_safely(): void {
	register_setting(
		'acme_group',
		'acme_headline',
		array( 'sanitize_callback' => 'sanitize_text_field' )
	);

	register_setting( 'acme_group', 'acme_legacy', 'sanitize_text_field' );
}

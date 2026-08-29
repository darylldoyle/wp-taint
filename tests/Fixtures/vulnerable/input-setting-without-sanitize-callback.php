<?php

/**
 * `options.php` writes whatever is posted for a registered setting. The
 * `sanitize_callback` is the only thing between the request and the option.
 *
 * There is no flow to follow here: core reads `$_POST`, core writes the option,
 * and the plugin's only involvement is the registration that told core to do
 * it. Taint analysis cannot find an absence.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_register_settings(): void {
	register_setting( 'acme_group', 'acme_headline' ); // wp-taint-expect wp.input.setting-without-sanitize authz

	register_setting( 'acme_group', 'acme_intro', array( 'type' => 'string' ) ); // wp-taint-expect wp.input.setting-without-sanitize authz
}

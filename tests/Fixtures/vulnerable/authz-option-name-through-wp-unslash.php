<?php

/**
 * `wp_unslash()` is a pass-through: its return is exactly as anchored as its
 * argument, which is to say not at all. Reading it as anchored missed the
 * commonest spelling of a request-named option write.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_write_option(): void {
	update_option( wp_unslash( $_POST['name'] ), 1 ); // wp-taint-expect wp.authz.arbitrary-option-write identifier
}

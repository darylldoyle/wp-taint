<?php

/**
 * Nothing in the scan calls this — WordPress does, on a hook core dispatches.
 * Its argument arrives from outside and nothing here says what it holds, which
 * is exactly the obligation the flag exists to report.
 *
 * A callback whose `apply_filters()` dispatch *is* in the scan is not an entry
 * point: the hook graph is folded into the call graph, so the arguments at the
 * dispatch are read like any other call's.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

add_action( 'admin_notices', __NAMESPACE__ . '\\acme_notice' );

function acme_notice( string $message = '' ): void {
	echo $message; // wp-taint-expect wp.output.unescaped-unknown unknown
}

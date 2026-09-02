<?php

/**
 * The same call one quote character away from safe.
 *
 * `esc_url()` encodes the apostrophe and `esc_url_raw()` does not, so a URL
 * carrying one closes the attribute here and opens the next.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_render_form( string $admin_url ): void {
	echo "<form name='acme' action='" . esc_url_raw( $admin_url ) . "' method='post'>"; // wp-taint-expect wp.xss.wrong-context-escape html
	echo '</form>';
}

<?php

/**
 * `esc_url_raw()` and `esc_url()` run the same filter. The only difference is
 * the display-context block, which encodes the apostrophe — everything that
 * matters for breaking out of a double-quoted attribute happens before it.
 *
 * The character filter strips `"`, `<`, `>`, backtick and space, and the scheme
 * allowlist rejects `javascript:`. There is no way out of this attribute.
 *
 * WP Super Cache writes this shape 32 times, and calling all 32 wrong is how a
 * rule teaches people to stop reading it.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_render_form( string $admin_url ): void {
	echo '<form name="acme" action="' . esc_url_raw( add_query_arg( 'tab', 'settings', $admin_url ) ) . '" method="post">';
	echo '</form>';
}

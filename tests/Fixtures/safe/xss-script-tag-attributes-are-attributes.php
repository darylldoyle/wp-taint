<?php

/**
 * A value between `<script` and its `>` is in an attribute, not in a script
 * body, and attribute rules apply to it.
 *
 * Counting the bare `<script` as opening a body called both of these wrong and
 * asked for JavaScript escaping on an id and a URL, which would be wrong in
 * turn: `esc_js()` on a URL does not stop `javascript:`.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_embed( string $id, string $src ): string {
	return sprintf(
		'<script id="%s" type="text/javascript" src="%s"></script>',
		esc_attr( $id ),
		esc_url( $src )
	);
}

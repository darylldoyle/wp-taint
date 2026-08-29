<?php

/**
 * The same callback escaping what it returns. Treating a block renderer's
 * return as output has to keep this silent, or it reports every correctly
 * written dynamic block in WordPress.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

register_block_type(
	'acme/card-safe',
	array( 'render_callback' => __NAMESPACE__ . '\\acme_render_card_safely' )
);

function acme_render_card_safely( $attributes, $content, $block ): string {
	$caption = get_post_meta( 1, 'acme_caption', true );

	return '<figcaption>' . esc_html( $caption ) . '</figcaption>';
}

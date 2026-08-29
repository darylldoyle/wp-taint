<?php

/**
 * A dynamic block's `render_callback` is the same shape as a shortcode handler:
 * WordPress calls it and prints what it returns, so the return is the output and
 * there is no `echo` in the plugin for a rule to find.
 *
 * `render_callback` appears in 110 files across the fifty-plugin corpus, so
 * being blind to it is being blind to most modern WordPress rendering.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

register_block_type(
	'acme/card',
	array( 'render_callback' => __NAMESPACE__ . '\\acme_render_card' )
);

function acme_render_card( $attributes, $content, $block ): string {
	$caption = get_post_meta( 1, 'acme_caption', true );

	return '<figcaption>' . $caption . '</figcaption>'; // wp-taint-expect wp.xss.unescaped-output html
}

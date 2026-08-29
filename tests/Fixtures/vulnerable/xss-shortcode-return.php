<?php

/**
 * WordPress prints what a shortcode callback returns, so the return is the
 * output and there is no later point at which it can be escaped.
 *
 * There is no `echo` here to find. `do_shortcode()` does the printing, and the
 * call that reaches this function is core's rather than the plugin's, so a rule
 * looking for output constructs sees nothing at all.
 *
 * The attributes come from the post body, which is chosen by anyone who can
 * edit a post.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

add_shortcode( 'acme_badge', __NAMESPACE__ . '\\acme_badge' );

function acme_badge( $atts ): string {
	$atts = shortcode_atts( array( 'color' => 'blue' ), $atts );

	return '<span style="color:' . $atts['color'] . '">badge</span>'; // wp-taint-expect wp.xss.unescaped-output html
}

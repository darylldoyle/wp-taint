<?php

/**
 * The same callback escaping its attribute. Treating a shortcode return as
 * output has to keep this silent, or it reports every correctly written
 * shortcode in WordPress.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

add_shortcode( 'acme_badge_safe', __NAMESPACE__ . '\\acme_badge_safe' );

function acme_badge_safe( $atts ): string {
	$atts = shortcode_atts( array( 'color' => 'blue' ), $atts );

	return '<span style="color:' . esc_attr( $atts['color'] ) . '">badge</span>';
}

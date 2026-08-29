<?php

/**
 * `escape_voided` only reports alongside `escaped`: the pair says one value was
 * escaped and then handed to a filter. A branch merge can produce that pair
 * from two paths where neither did both.
 *
 * The first branch never escapes anything. The second never goes near a filter.
 * The finding a union manufactures here tells the reader to fix an ordering
 * that no path has, and three blocks in a real client theme are exactly this
 * shape — an attachment image with a fallback to a plain URL.
 */

declare(strict_types=1);

namespace Acme\Fixtures;

function acme_media( $media_id, string $url, string $alt ): void {
	$html = '';

	if ( is_numeric( $media_id ) ) {
		$html = wp_get_attachment_image( (int) $media_id, 'large' );
	}

	if ( '' === $html && '' !== $url ) {
		$html = sprintf( '<img src="%s" alt="%s" />', esc_url( $url ), esc_attr( $alt ) );
	}

	echo $html;
}

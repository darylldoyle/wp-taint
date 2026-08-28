<?php
/**
 * Fixture: escaped output passed through do_shortcode()/wptexturize()-style
 * post-processing that can re-introduce arbitrary content via a registered
 * shortcode. The escape happened too early.
 */

function fx_escape_then_do_shortcode( $value ) {
	$safe = esc_html( $value );
	// do_shortcode expands [..] tags; a registered shortcode can emit raw HTML,
	// so the escaped string is no longer the final trusted output.
	// ruleid: wp.output.escape-voided
	echo do_shortcode( $safe );
}

// wp_kses_post AFTER do_shortcode would be defensible; here order is wrong.
function fx_do_shortcode_then_kses( $value ) {
	$expanded = do_shortcode( $value );
	// ok: wp.output.escape-voided
	echo wp_kses_post( $expanded );
}

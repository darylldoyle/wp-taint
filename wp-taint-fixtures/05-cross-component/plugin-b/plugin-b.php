<?php
/**
 * Plugin Name: FX Plugin B (sink side)
 * Listens to plugin-a's action and filter. This is where taint from plugin-a
 * reaches an output sink. The vulnerability only exists when both plugins are
 * scanned together.
 */

// Sink for the cross-component action flow. $payload originates as raw $_POST
// inside plugin-a::fx_a_dispatch().
function fx_b_show_receipt( $payload ) {
	// ruleid: wp.xcomp.sink-from-action
	echo '<div class="receipt">Received: ' . $payload . '</div>';
}
add_action( 'fx_a_after_submit', 'fx_b_show_receipt' );

// plugin-b feeds a raw request value INTO plugin-a's greeting filter. plugin-a
// then echoes it unescaped. Taint source here, sink in plugin-a.
function fx_b_inject_greeting( $greeting ) {
	// ruleid: wp.xcomp.filter-injects-taint
	return $greeting . ' ' . ( $_GET['name'] ?? '' );
}
add_filter( 'fx_a_greeting', 'fx_b_inject_greeting' );

// Correct listener for contrast: escapes at its own sink. SAFE.
function fx_b_show_receipt_safe( $payload ) {
	// ok: wp.xcomp.sink-from-action
	echo '<div class="receipt">Received: ' . esc_html( $payload ) . '</div>';
}
add_action( 'fx_a_after_submit', 'fx_b_show_receipt_safe' );

<?php
/**
 * Fixture: taint reaching a sink inside a hook/callback closure. Probes whether
 * the analyser follows taint into add_action/add_filter callbacks and anonymous
 * functions, which is a common blind spot.
 */

function fx_register_hooks() {
	$raw = $_GET['msg'] ?? '';

	// Taint captured by a closure, echoed on the hook. VULNERABLE.
	add_action( 'wp_footer', function () use ( $raw ) {
		// ruleid: wp.flow.xss
		echo '<div class="notice">' . $raw . '</div>';
	} );

	// Same, but escaped in the closure. SAFE.
	add_action( 'wp_footer', function () use ( $raw ) {
		// ok: wp.flow.xss
		echo '<div class="notice">' . esc_html( $raw ) . '</div>';
	} );
}

// shortcode callback: $atts values are user-controllable via post content.
function fx_shortcode( $atts ) {
	$atts = shortcode_atts( array( 'color' => 'blue' ), $atts );
	// ruleid: wp.flow.xss
	return '<span style="color:' . $atts['color'] . '">text</span>';
}
add_shortcode( 'fx_badge', 'fx_shortcode' );

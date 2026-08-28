<?php
/**
 * Fixture: taint that crosses function boundaries. Probes call-graph
 * propagation, return-value taint, and taint carried through parameters.
 */

// Taint returned from a helper.
function fx_get_raw_param() {
	return $_GET['name'] ?? '';
}

function fx_render_from_helper() {
	$name = fx_get_raw_param();
	// ruleid: wp.flow.xss
	echo '<p>' . $name . '</p>';
}

// Taint passed down through two layers, sanitised in the middle layer.
function fx_sanitise_passthru( $raw ) {
	return sanitize_text_field( $raw );
}

function fx_render_sanitised_passthru() {
	$clean = fx_sanitise_passthru( wp_unslash( $_POST['title'] ?? '' ) );
	// esc still required by convention; sanitiser present so XSS class defused
	// but late-escape missing.
	// ruleid: wp.flow.output-not-escaped
	echo '<h1>' . $clean . '</h1>';
}

// Escaper applied inside the callee; caller echoes the returned safe value.
function fx_escape_and_return( $raw ) {
	return esc_html( $raw );
}

function fx_render_escaped_callee() {
	$safe = fx_escape_and_return( get_option( 'fx_title' ) );
	// ok: wp.flow.xss
	echo '<h1>' . $safe . '</h1>';
}

// Taint flows through an array element and is extracted later — probes
// field-sensitivity.
function fx_array_carry() {
	$ctx = array( 'q' => $_GET['q'] ?? '', 'safe' => 'literal' );

	// ruleid: wp.flow.xss
	echo $ctx['q'];

	// The 'safe' key holds a literal, never tainted. Field-sensitivity means
	// this must NOT be flagged even though it shares the array with a tainted key.
	$literal = $ctx['safe'];

	// ok: wp.flow.xss
	echo $literal;
}

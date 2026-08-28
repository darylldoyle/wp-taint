<?php
/**
 * Plugin Name: FX Plugin A (source side)
 * Collects input and hands it to other components via a custom action and a
 * stored option. Nothing here escapes — that is intentional; the sinks live in
 * plugin-b and the theme.
 */

// Custom action fires with a RAW request value. Any listener that echoes the
// payload without escaping is exposed. Source of a cross-component flow.
function fx_a_dispatch() {
	$payload = $_POST['fx_payload'] ?? '';
	// This is a source; the taint leaves the file here.
	// ruleid: wp.xcomp.action-carries-taint
	do_action( 'fx_a_after_submit', $payload );
}
add_action( 'admin_post_fx_a_submit', 'fx_a_dispatch' );

// Stores a raw value under a well-known option name that the theme reads.
function fx_a_persist() {
	// ruleid: wp.input.unsanitised
	update_option( 'fx_a_banner', $_POST['banner'] ?? '' );
}
add_action( 'admin_post_fx_a_save_banner', 'fx_a_persist' );

// A filter that plugin-a exposes so others can adjust a value it will later
// echo itself. plugin-b hooks this and can return arbitrary markup.
function fx_a_render_greeting() {
	$greeting = apply_filters( 'fx_a_greeting', 'Hello' );
	// plugin-a trusts the filter output and echoes it unescaped. The taint may
	// be introduced by a *different* plugin's callback.
	// ruleid: wp.xcomp.filter-return-unescaped
	echo '<p class="greeting">' . $greeting . '</p>';
}

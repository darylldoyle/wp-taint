<?php
/**
 * Theme functions. Reads an option that plugin-a wrote from raw input and
 * exposes it to templates. The read is tainted because the paired write
 * (plugin-a::fx_a_persist) was tainted.
 */

function fx_theme_get_banner() {
	// Tainted read: fx_a_banner was stored raw in plugin-a.
	return get_option( 'fx_a_banner' );
}

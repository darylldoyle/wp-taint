<?php
/**
 * Fixture: attribute-boundary and URI-scheme edge cases for the escaper
 * context model. Mix of safe and vulnerable.
 */

function fx_attr_uri( $value, $url ) {
	// Unquoted attribute with esc_attr: esc_attr does not add quotes, so an
	// unquoted sink is still breakable. VULNERABLE.
	// ruleid: wp.output.wrong-context
	echo "<input value=" . esc_attr( $value ) . ">";

	// Quoted attribute with esc_attr: correct. SAFE.
	// ok: wp.output.unescaped
	echo '<input value="' . esc_attr( $value ) . '">';

	// esc_url strips javascript:/data: schemes → SAFE for href.
	// ok: wp.output.unescaped
	printf( '<a href="%s">x</a>', esc_url( $url ) );

	// Raw variable directly into a style attribute — CSS/expression context,
	// esc_attr is insufficient for all style payloads but no escaper at all
	// here. VULNERABLE.
	// ruleid: wp.output.unescaped
	echo '<div style="width:' . $value . '"></div>';

	// data-* attribute holding JSON: needs esc_attr around encoded JSON.
	// Present and correct. SAFE.
	// ok: wp.output.unescaped
	printf( '<div data-config="%s"></div>', esc_attr( wp_json_encode( $value ) ) );
}

<?php
/**
 * Fixture: THE house-convention cases. Output is correctly escaped, then passed
 * back through a filter/hook that makes it user-modifiable again. Under the
 * "escape is null and void if re-mutable" rule, these are VULNERABLE even
 * though an esc_* call is visibly present.
 *
 * This is the class most generic analysers get wrong: they see esc_html() and
 * stop. The analyser must model "escaped value re-enters a mutation point → taint
 * is reintroduced → must be re-escaped after the last mutation".
 */

// Escaped, then apply_filters lets any hooked callback rewrite it before echo.
function fx_escape_then_filter( $value ) {
	$safe = esc_html( $value );
	// A third-party callback on this filter can return arbitrary markup.
	$maybe_mutated = apply_filters( 'fx_the_label', $safe );
	// ruleid: wp.output.escape-voided
	echo $maybe_mutated;
}

// Correct ordering: filter first, escape last. SAFE.
function fx_filter_then_escape( $value ) {
	$filtered = apply_filters( 'fx_the_label', $value );
	// ok: wp.output.escape-voided
	echo esc_html( $filtered );
}

// Escaped into a variable, concatenated with a filtered (unescaped) fragment,
// echoed as one string. The filtered fragment voids the safety of the whole.
function fx_escape_then_concat_filtered( $value ) {
	$safe = esc_html( $value );
	$suffix = apply_filters( 'fx_suffix', '' ); // hookable, unescaped
	// ruleid: wp.output.escape-voided
	echo $safe . $suffix;
}

// Escaped value stored, then run through a *second* mutation via
// str_replace of a placeholder that a filter supplies. Voided.
function fx_escape_then_token_replace( $value ) {
	$safe = esc_html( $value );
	$replacement = apply_filters( 'fx_token_value', '{{TOKEN}}' );
	// ruleid: wp.output.escape-voided
	echo str_replace( '{{TOKEN}}', $replacement, $safe );
}

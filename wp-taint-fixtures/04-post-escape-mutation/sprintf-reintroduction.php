<?php
/**
 * Fixture: escaped value used as a sprintf/printf FORMAT string, while a
 * tainted, unescaped value is supplied as the substitution. The escaped part is
 * safe; the injected argument is not. Probes argument-vs-format taint tracking
 * after an escape has occurred.
 */

function fx_escaped_format_tainted_arg( $label, $raw_url ) {
	$safe_label = esc_html( $label );
	// %s is filled with an unescaped tainted URL — escape of the label is
	// irrelevant to the injected arg.
	// ruleid: wp.output.escape-voided
	printf( '<a href="%s">' . $safe_label . '</a>', $raw_url );
}

// Both parts handled. SAFE.
function fx_escaped_format_escaped_arg( $label, $raw_url ) {
	$safe_label = esc_html( $label );
	// ok: wp.output.escape-voided
	printf( '<a href="%s">' . $safe_label . '</a>', esc_url( $raw_url ) );
}

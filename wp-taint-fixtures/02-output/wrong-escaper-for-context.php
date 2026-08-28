<?php
/**
 * Fixture: an escaper is present but wrong for the sink context.
 * These are the subtle cases — a naive analyser sees "an esc_* call, so safe"
 * and misses that the context defeats it.
 */

function fx_context_mismatch( $value, $url ) {
	// esc_html inside a JS context does not neutralise a string-breakout payload
	// like  ";alert(1);//
	// ruleid: wp.output.wrong-context
	echo '<script>var x = "' . esc_html( $value ) . '";</script>';

	// esc_attr used for an href: javascript: URIs survive attribute escaping.
	// ruleid: wp.output.wrong-context
	printf( '<a href="%s">x</a>', esc_attr( $url ) );

	// esc_html on an unquoted attribute: payload needs no quotes to break out
	// (e.g.  x onmouseover=alert(1) ).
	// ruleid: wp.output.wrong-context
	printf( '<div data-v=%s></div>', esc_html( $value ) );

	// esc_js is for inline event handlers / single-quoted JS strings; using
	// esc_url_raw where JS is expected leaves a breakout.
	// ruleid: wp.output.wrong-context
	echo "<button onclick='doThing(\"" . esc_url_raw( $value ) . "\")'>go</button>";

	// Correct pairing, present for contrast — must NOT flag.
	// ok: wp.output.wrong-context
	echo '<script>var u = ' . wp_json_encode( $value ) . ';</script>';

	// ok: wp.output.wrong-context
	printf( '<a href="%s">x</a>', esc_url( $url ) );
}

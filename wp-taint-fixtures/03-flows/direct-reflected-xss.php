<?php
/**
 * Fixture: reflected XSS — source to sink within one function, no sanitiser.
 * The canonical smoke test. VULNERABLE.
 */

function fx_search_header() {
	$q = $_GET['s'] ?? '';
	// ruleid: wp.flow.xss
	echo '<h2>Results for: ' . $q . '</h2>';
}

// Sanitised at source, still unescaped at sink. sanitize_text_field strips
// tags so this specific payload class is largely defused, but WP convention
// is late-escaping regardless — a strict checker flags the missing escape.
function fx_search_header_convention() {
	$q = sanitize_text_field( wp_unslash( $_GET['s'] ?? '' ) );
	// ruleid: wp.flow.output-not-escaped
	echo '<h2>Results for: ' . $q . '</h2>';
}

// Correct: sanitised at input AND escaped at output. SAFE.
function fx_search_header_good() {
	$q = sanitize_text_field( wp_unslash( $_GET['s'] ?? '' ) );
	// ok: wp.flow.xss
	echo '<h2>Results for: ' . esc_html( $q ) . '</h2>';
}

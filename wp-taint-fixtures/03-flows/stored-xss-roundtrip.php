<?php
/**
 * Fixture: stored XSS across a persistence boundary.
 * Taint enters via $_POST, is stored raw, later read back and echoed raw.
 * The analyser must treat option/meta reads as tainted when the paired write
 * was tainted (or, more conservatively, treat all persisted reads as tainted).
 */

// --- write side ---
function fx_store_bio() {
	// ruleid: wp.input.unsanitised
	update_user_meta( get_current_user_id(), 'fx_bio', wp_unslash( $_POST['bio'] ) );
}

// --- read side (potentially a different request entirely) ---
function fx_show_bio( $user_id ) {
	$bio = get_user_meta( $user_id, 'fx_bio', true );
	// ruleid: wp.output.unescaped
	echo '<div class="bio">' . $bio . '</div>';
}

// Correct roundtrip: escape on the way out even though stored. SAFE.
function fx_show_bio_good( $user_id ) {
	$bio = get_user_meta( $user_id, 'fx_bio', true );
	// ok: wp.output.unescaped
	echo '<div class="bio">' . wp_kses_post( $bio ) . '</div>';
}

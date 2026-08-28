<?php
/**
 * Fixture: path-sensitive sanitisation. Probes whether the analyser tracks
 * taint per branch rather than assuming one sanitiser call cleans a variable
 * for the whole function.
 */

// Only one branch sanitises: the else path stays tainted.
function fx_branch_partial() {
	if ( isset( $_POST['strict'] ) ) {
		$value = sanitize_text_field( wp_unslash( $_POST['value'] ) );
	} else {
		$value = wp_unslash( $_POST['value'] );
	}
	// ruleid: wp.input.unsanitised
	update_option( 'fx_branch_partial', $value );
}

// Both branches sanitise: clean on every path.
function fx_branch_full() {
	if ( isset( $_POST['numeric'] ) ) {
		$value = absint( $_POST['value'] );
	} else {
		$value = sanitize_text_field( wp_unslash( $_POST['value'] ) );
	}
	// ok: wp.input.unsanitised
	update_option( 'fx_branch_full', $value );
}

// Guard-clause validation: non-conforming values never reach the write.
function fx_guard_clause() {
	$id = wp_unslash( $_GET['id'] ?? '' );
	if ( ! ctype_digit( $id ) ) {
		return;
	}
	// ok: wp.input.unsanitised
	update_option( 'fx_guarded_id', $id );
}

// Strict whitelist comparison constrains the value to known constants.
function fx_whitelist_strict() {
	$mode = wp_unslash( $_GET['mode'] ?? '' );
	if ( ! in_array( $mode, array( 'grid', 'list', 'table' ), true ) ) {
		$mode = 'grid';
	}
	// ok: wp.input.unsanitised
	update_option( 'fx_display_mode', $mode );
}

// Loose in_array(): type juggling can smuggle values past the check
// (e.g. '0x1A' == 26 comparisons on older semantics, '1e1' == 10).
// Stretch case: flagging this requires modelling comparison strictness.
function fx_whitelist_loose() {
	$level = wp_unslash( $_GET['level'] ?? '' );
	if ( ! in_array( $level, array( 1, 2, 3 ) ) ) {
		$level = 1;
	}
	// todoruleid: wp.input.weak-sanitiser
	update_option( 'fx_level', $level );
}

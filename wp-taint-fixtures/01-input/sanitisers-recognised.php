<?php
/**
 * Fixture: core sanitisers correctly neutralise input.
 * Every case here is SAFE. A finding on any annotated line is a false positive.
 * Verdict context: input handling only — values are persisted, not echoed.
 */

function fx_save_settings() {
	// ok: wp.input.unsanitised
	update_option( 'fx_title', sanitize_text_field( wp_unslash( $_POST['title'] ?? '' ) ) );

	// ok: wp.input.unsanitised
	update_option( 'fx_count', absint( $_GET['count'] ?? 0 ) );

	// ok: wp.input.unsanitised
	update_option( 'fx_offset', (int) $_GET['offset'] );

	// ok: wp.input.unsanitised
	update_option( 'fx_email', sanitize_email( wp_unslash( $_POST['email'] ) ) );

	// ok: wp.input.unsanitised
	update_option( 'fx_mode', sanitize_key( $_REQUEST['mode'] ) );

	// ok: wp.input.unsanitised
	update_option( 'fx_endpoint', esc_url_raw( wp_unslash( $_POST['endpoint'] ) ) );

	// ok: wp.input.unsanitised
	update_option( 'fx_bio', sanitize_textarea_field( wp_unslash( $_POST['bio'] ) ) );

	// ok: wp.input.unsanitised
	update_post_meta( 42, '_fx_slug', sanitize_title( wp_unslash( $_POST['slug'] ) ) );

	// ok: wp.input.unsanitised
	update_option( 'fx_ids', array_map( 'absint', (array) ( $_POST['ids'] ?? array() ) ) );

	// ok: wp.input.unsanitised
	update_option( 'fx_html', wp_kses_post( wp_unslash( $_POST['content'] ) ) );
}

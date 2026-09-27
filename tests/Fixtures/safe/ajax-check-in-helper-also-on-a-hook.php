<?php

/**
 * The handler fires an action that its own check is registered on, and then
 * calls the check by name as well. The direct call is what counts, and it is a
 * real check.
 */

add_action( 'wp_ajax_acme_save_note', 'acme_save_note' );

add_action( 'acme_before_save', 'acme_require_editor' );

function acme_require_editor() {
	if ( ! current_user_can( 'edit_posts' ) ) {
		wp_send_json_error( null, 403 );
	}
}

function acme_save_note() {
	do_action( 'acme_before_save' );

	acme_require_editor();

	update_option( 'acme_note', sanitize_text_field( $_POST['note'] ) );
}

<?php
/**
 * An action whose callback escapes before output.
 */

add_action( 'acme_note_saved', 'acme_print_note' );

function acme_print_note( $note ) {
	echo esc_html( $note );
}

function acme_save_note() {
	do_action( 'acme_note_saved', $_POST['note'] );
}

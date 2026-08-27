<?php
/**
 * do_action() flows its arguments into every callback's parameters, so a sink
 * inside the callback is reported with a trace that crosses the hook.
 */

add_action( 'acme_note_saved', 'acme_log_note' );

function acme_log_note( $note ) {
	echo $note; // wp-taint-expect wp.xss.unescaped-output html
}

function acme_save_note() {
	do_action( 'acme_note_saved', $_POST['note'] );
}

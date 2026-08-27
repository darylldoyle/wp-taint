<?php
/**
 * Resolving the dispatcher has to work in both directions: a callee that
 * escapes is as important to follow as one that does not.
 */
function acme_render_safe( $value ) {
	echo esc_html( $value );
}

function acme_dispatch() {
	call_user_func( 'acme_render_safe', $_GET['message'] );
}

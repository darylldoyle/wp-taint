<?php
/**
 * call_user_func() is a call to whatever the callable names, not a call to
 * call_user_func. Stopping at the dispatcher loses the flow entirely.
 */
function acme_render_raw( $value ) {
	echo $value; // wp-taint-expect wp.xss.unescaped-output html
}

function acme_dispatch() {
	call_user_func( 'acme_render_raw', $_GET['message'] );
}

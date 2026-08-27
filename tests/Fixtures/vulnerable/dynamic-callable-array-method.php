<?php
/**
 * The array callable form, resolved through the receiver's class.
 */
class Acme_Widget {

	public function render( $value ) {
		echo $value; // wp-taint-expect wp.xss.unescaped-output html
	}

	public function dispatch() {
		call_user_func( array( $this, 'render' ), $_POST['title'] );
	}
}

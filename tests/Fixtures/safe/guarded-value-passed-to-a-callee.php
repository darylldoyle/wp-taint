<?php
/**
 * The id is checked to be digits and then handed to a helper that prints it.
 * The helper sees what the check let through.
 */

function acme_print_id( $id ) {
	echo 'Order #' . $id;
}

function acme_order_page() {
	$id = $_GET['id'];

	if ( ! ctype_digit( $id ) ) {
		return;
	}

	acme_print_id( $id );
}

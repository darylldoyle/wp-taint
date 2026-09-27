<?php
/**
 * UpdraftPlus escapes a table name by doubling its backticks and wrapping it
 * in backticks. That is MySQL's rule for a quoted identifier, and the result
 * carries its own quotes, so it is safe wherever the query puts it.
 */

class UpdraftPlus_Database_Utility {
	public static function escape_table_name( $table ) {
		return '`' . str_replace( '`', '``', $table ) . '`';
	}
}

function acme_count_rows() {
	global $wpdb;

	$table = UpdraftPlus_Database_Utility::escape_table_name( $_GET['table'] );

	return $wpdb->get_var( "SELECT COUNT(*) FROM $table" );
}

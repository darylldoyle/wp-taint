<?php
/**
 * Fixture: SQL injection via $wpdb. Probes the SQLi sink model and prepare()
 * recognition. Mix of safe and vulnerable.
 */

global $wpdb;

function fx_sqli_concat( $wpdb ) {
	$id = $_GET['id'] ?? '';
	// ruleid: wp.flow.sqli
	$wpdb->query( "DELETE FROM {$wpdb->posts} WHERE ID = " . $id );
}

function fx_sqli_interpolated( $wpdb ) {
	$slug = $_GET['slug'] ?? '';
	// ruleid: wp.flow.sqli
	$wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE post_name = '$slug'" );
}

// prepare() with placeholders — SAFE.
function fx_sqli_prepared( $wpdb ) {
	$id = absint( $_GET['id'] ?? 0 );
	// ok: wp.flow.sqli
	$wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE ID = %d", $id ) );
}

// prepare() misused: value concatenated INTO the query string before prepare
// sees it. The placeholder is a decoy; taint already reached the SQL. VULNERABLE.
function fx_sqli_fake_prepare( $wpdb ) {
	$order = $_GET['order'] ?? 'ASC';
	// ruleid: wp.flow.sqli
	$wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} ORDER BY post_date $order LIMIT %d", 10 ) );
}

// esc_sql on a value used inside quotes is acceptable for values but NOT for
// identifiers/keywords like ORDER BY direction. This one is a value → SAFE-ish;
// convention still prefers prepare. Marked ok for the SQLi rule specifically.
function fx_sqli_esc_sql_value( $wpdb ) {
	$name = esc_sql( wp_unslash( $_GET['name'] ?? '' ) );
	// ok: wp.flow.sqli
	$wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE post_title = '$name'" );
}

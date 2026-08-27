<?php

/**
 * The counterpart to sql-prepare-table-from-helper: the helper's return value
 * really does come from the request.
 *
 * Loosening the format-string check must not lose this.
 */

function acme_table_for_request()
{
    return 'wp_' . $_GET['table'];
}

global $wpdb;

$table = acme_table_for_request();

$wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE id = %d", 1)); // wp-taint-expect wp.sqli.prepare-non-literal sql

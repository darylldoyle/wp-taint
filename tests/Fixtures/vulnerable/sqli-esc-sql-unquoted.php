<?php

/**
 * esc_sql() escapes quotes and backslashes. With no quotes around the value
 * there is nothing to escape, and `1 OR 1=1` reaches the database intact.
 */

function acme_get_row()
{
    global $wpdb;

    return $wpdb->get_row( // wp-taint-expect wp.sqli.unprepared-query sql
        'SELECT * FROM acme_log WHERE ID = ' . esc_sql($_GET['id']),
    );
}

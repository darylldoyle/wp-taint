<?php

/**
 * The same escaper doing the job it is for: the value sits inside quotes, so
 * escaping them is a real defence.
 */

function acme_get_row_safe()
{
    global $wpdb;

    return $wpdb->get_row("SELECT * FROM acme_log WHERE name = '" . esc_sql($_GET['name']) . "'");
}

<?php

/**
 * SQL injection into wpdb::get_col.
 */

global $wpdb;

$type = $_REQUEST['type'];

$ids = $wpdb->get_col("SELECT id FROM {$wpdb->prefix}acme_items WHERE type = '{$type}'"); // wp-taint-expect wp.sqli.wpdb-query sql

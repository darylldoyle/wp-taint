<?php

/**
 * SQL injection into wpdb::get_results.
 */

global $wpdb;

$order = $_GET['orderby'];

$rows = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}acme_items ORDER BY {$order}"); // wp-taint-expect wp.sqli.wpdb-query sql

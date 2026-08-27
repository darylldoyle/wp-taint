<?php

/**
 * SQL injection: request data interpolated straight into a query string.
 */

global $wpdb;

$id = $_GET['post_id'];

$wpdb->query("DELETE FROM {$wpdb->prefix}acme_log WHERE post_id = {$id}"); // wp-taint-expect wp.sqli.wpdb-query sql

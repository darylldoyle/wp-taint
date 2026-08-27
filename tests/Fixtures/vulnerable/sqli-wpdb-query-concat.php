<?php

/**
 * SQL injection through concatenation rather than interpolation.
 */

global $wpdb;

$status = $_POST['status'];

$wpdb->query('UPDATE ' . $wpdb->prefix . "acme_jobs SET status = '" . $status . "'"); // wp-taint-expect wp.sqli.wpdb-query sql

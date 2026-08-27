<?php

/**
 * SQL injection into wpdb::get_var.
 */

global $wpdb;

$email = $_POST['email'];

$count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->users} WHERE user_email = '{$email}'"); // wp-taint-expect wp.sqli.wpdb-query sql

<?php

/**
 * sanitize_text_field() clears html, not sql.
 */

global $wpdb;

$name = sanitize_text_field($_POST['name']);

$wpdb->get_results("SELECT * FROM {$wpdb->prefix}acme_people WHERE name = '{$name}'"); // wp-taint-expect wp.sqli.wpdb-query sql

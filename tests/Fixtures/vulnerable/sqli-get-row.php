<?php

/**
 * SQL injection into wpdb::get_row.
 */

global $wpdb;

$row = $wpdb->get_row('SELECT * FROM ' . $wpdb->prefix . 'acme_items WHERE slug = "' . $_GET['slug'] . '"'); // wp-taint-expect wp.sqli.wpdb-query sql

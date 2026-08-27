<?php

/**
 * wpdb::prepare() only protects when its first argument is a literal string
 * containing placeholders. Building that first argument from user input makes
 * prepare() a sink rather than a sanitizer.
 *
 * This is a real and common WordPress bug class.
 */

global $wpdb;

$column = $_GET['orderby'];

$sql = "SELECT * FROM {$wpdb->prefix}acme_items ORDER BY {$column} LIMIT %d";

$wpdb->get_results($wpdb->prepare($sql, 10)); // wp-taint-expect wp.sqli.prepare-non-literal sql

<?php

/**
 * The same bug written inline, which is how it usually appears in the wild.
 */

global $wpdb;

$table = $_POST['table'];

$wpdb->query($wpdb->prepare("SELECT * FROM {$table} WHERE id = %d", 1)); // wp-taint-expect wp.sqli.prepare-non-literal sql

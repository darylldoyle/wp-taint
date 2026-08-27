<?php

/**
 * esc_sql() clears sql taint. prepare() is preferable, but this is not a
 * vulnerability.
 */

global $wpdb;

$slug = esc_sql($_GET['slug']);

$wpdb->get_results("SELECT * FROM wp_acme_items WHERE slug = '{$slug}'");

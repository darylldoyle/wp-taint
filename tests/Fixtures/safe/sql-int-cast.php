<?php

/**
 * The cast written as a cast rather than a function call.
 */

global $wpdb;

$limit = (int) $_GET['limit'];

$wpdb->get_results('SELECT * FROM wp_acme_items LIMIT ' . $limit);

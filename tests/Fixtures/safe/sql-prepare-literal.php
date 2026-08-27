<?php

/**
 * The correct wpdb::prepare() idiom: a literal format string with placeholders
 * and the untrusted value passed as an argument.
 */

global $wpdb;

$id = $_GET['post_id'];

$wpdb->get_results($wpdb->prepare('SELECT * FROM wp_acme_items WHERE post_id = %d', $id));

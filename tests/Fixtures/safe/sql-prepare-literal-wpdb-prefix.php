<?php

/**
 * Interpolating $wpdb->prefix into the format string is the standard, correct
 * WordPress idiom. The table name is not attacker-controlled, so prepare()
 * still protects the query.
 *
 * Flagging this would be a guaranteed false positive on nearly every plugin.
 */

global $wpdb;

$slug = $_GET['slug'];

$wpdb->get_results(
    $wpdb->prepare("SELECT * FROM {$wpdb->prefix}acme_items WHERE slug = %s", $slug)
);

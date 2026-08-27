<?php

/**
 * The str_repeat() variant of the same placeholder idiom.
 */

global $wpdb;

$ids = array_map('absint', (array) $_POST['ids']);

$placeholders = rtrim(str_repeat('%d,', count($ids)), ',');

$wpdb->get_results(
    $wpdb->prepare("SELECT * FROM {$wpdb->prefix}acme_items WHERE id IN ({$placeholders})", $ids)
);

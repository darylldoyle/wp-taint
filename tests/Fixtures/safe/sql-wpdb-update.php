<?php

/**
 * wpdb::update() likewise escapes internally.
 */

global $wpdb;

$wpdb->update(
    $wpdb->prefix . 'acme_items',
    ['title' => $_POST['title']],
    ['id' => $_POST['id']]
);

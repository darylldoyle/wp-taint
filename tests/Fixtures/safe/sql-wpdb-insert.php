<?php

/**
 * wpdb::insert() escapes its data internally. Flagging it is a guaranteed
 * false positive, so it is encoded as explicitly safe.
 */

global $wpdb;

$wpdb->insert(
    $wpdb->prefix . 'acme_items',
    [
        'title' => $_POST['title'],
        'body' => $_POST['body'],
    ],
    ['%s', '%s']
);

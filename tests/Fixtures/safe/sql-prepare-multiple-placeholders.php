<?php

/**
 * Several placeholders, several untrusted arguments.
 */

global $wpdb;

$wpdb->query(
    $wpdb->prepare(
        "UPDATE {$wpdb->prefix}acme_jobs SET status = %s, note = %s WHERE id = %d",
        $_POST['status'],
        $_POST['note'],
        $_POST['id']
    )
);

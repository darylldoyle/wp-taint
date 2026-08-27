<?php

/**
 * A WHERE clause assembled from already-prepared fragments.
 *
 * The outer format string interpolates $comment_type_where, which is itself
 * built entirely from prepare() output. prepare() output is escaped SQL, so
 * concatenating it into another format string is safe.
 *
 * Taken from Akismet, where we reported it as critical on the first corpus run.
 */

global $wpdb;

$comment_type_where = '';

foreach ((array) $_GET['excluded_types'] as $excluded_comment_type) {
    $comment_type_where .= $wpdb->prepare(' AND comment_type <> %s ', $excluded_comment_type);
}

$count = (int) $wpdb->get_var(
    $wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->comments} WHERE user_id = %d AND comment_approved = 1" . $comment_type_where,
        absint($_GET['user_id'])
    )
);

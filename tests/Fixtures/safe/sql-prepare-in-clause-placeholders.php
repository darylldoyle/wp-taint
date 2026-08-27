<?php

/**
 * The canonical way to write a prepared IN (...) clause.
 *
 * The format string is not a literal — it interpolates $format_string — but
 * every character of $format_string came from the literals ', ' and '%s'. Only
 * its length depends on the data.
 *
 * This is what Akismet and All in One SEO both do, and calling it a non-literal
 * prepare() format string was the single largest false positive class on the
 * first corpus run.
 */

global $wpdb;

$comment_ids = array_map('absint', (array) $_POST['comment_ids']);

$format_string = implode(', ', array_fill(0, count($comment_ids), '%s'));

$wpdb->query(
    $wpdb->prepare(
        "DELETE FROM {$wpdb->comments} WHERE comment_id IN ( " . $format_string . ' )',
        $comment_ids
    )
);

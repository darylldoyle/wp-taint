<?php

/**
 * Interprocedural: the helper prepares the query, so the caller is safe.
 */

function acme_find_item($slug)
{
    global $wpdb;

    return $wpdb->get_row(
        $wpdb->prepare("SELECT * FROM {$wpdb->prefix}acme_items WHERE slug = %s", $slug)
    );
}

$item = acme_find_item($_GET['slug']);

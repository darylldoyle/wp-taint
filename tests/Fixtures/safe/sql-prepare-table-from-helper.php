<?php

/**
 * A table name from a helper, interpolated into a prepare() format string.
 *
 * Not a literal, and not dangerous: the engine can follow acme_table() to its
 * definition and see that nothing attacker-controlled reaches it.
 *
 * "Not a string literal" is not the same as "unsafe". Conflating the two
 * produced 532 critical findings across the corpus, nearly all on this shape.
 */

function acme_table()
{
    global $wpdb;

    return $wpdb->prefix . 'acme_items';
}

global $wpdb;

$table = acme_table();

$row = $wpdb->get_row(
    $wpdb->prepare("SELECT * FROM {$table} WHERE slug = %s", $_GET['slug'])
);

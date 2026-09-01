<?php

/**
 * The quote that protects esc_sql() lives in a helper's return value.
 *
 * The fragment before the escaped value is a call, not a literal — but it
 * folds to exactly one string, and that string ends inside an open quote, so
 * the escaped value lands where esc_sql() is a real defence.
 */

function acme_quoted_head()
{
    return "config WHERE name = '";
}

function acme_lookup_quoted()
{
    global $wpdb;

    return $wpdb->get_row('SELECT * FROM ' . acme_quoted_head() . esc_sql($_GET['n']) . "'");
}

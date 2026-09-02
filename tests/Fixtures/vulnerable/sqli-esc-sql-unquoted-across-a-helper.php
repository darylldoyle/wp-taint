<?php

/**
 * The helper's fragment leaves the position unquoted, and esc_sql() defends
 * nothing there: `1 OR 1=1` has no quote to escape and reaches the database
 * whole. Folding the helper's constant return must carry the dangerous state
 * as faithfully as the safe one.
 */

function acme_bare_clause()
{
    return ' WHERE id = ';
}

function acme_lookup_bare()
{
    global $wpdb;

    return $wpdb->get_row('SELECT * FROM t' . acme_bare_clause() . esc_sql($_GET['id'])); // wp-taint-expect wp.sqli.unprepared-query sql
}

<?php

/**
 * SQL injection crossing a function boundary.
 */

function acme_build_where($value)
{
    return " WHERE slug = '" . $value . "'";
}

global $wpdb;

$wpdb->query('SELECT * FROM ' . $wpdb->prefix . 'acme_items' . acme_build_where($_GET['slug'])); // wp-taint-expect wp.sqli.wpdb-query sql

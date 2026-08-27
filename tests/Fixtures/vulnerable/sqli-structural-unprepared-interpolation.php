<?php

/**
 * The structural check for interpolation into a query, independent of whether
 * taint analysis can reach the value. $order comes from a helper the engine
 * cannot resolve, but the shape alone is reportable.
 */

global $wpdb;

$order = acme_unresolvable_helper();

$wpdb->get_results("SELECT * FROM {$wpdb->prefix}acme_items ORDER BY {$order}"); // wp-taint-expect wp.sqli.unprepared-query sql

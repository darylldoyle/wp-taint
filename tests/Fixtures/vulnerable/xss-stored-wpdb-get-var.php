<?php

/**
 * Stored XSS via a direct database read.
 */

global $wpdb;

$label = $wpdb->get_var('SELECT label FROM ' . $wpdb->prefix . 'acme_items LIMIT 1');

echo '<td>' . $label . '</td>'; // wp-taint-expect wp.xss.unescaped-output html

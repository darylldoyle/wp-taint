<?php

/**
 * esc_html() clears html taint. It does nothing for sql taint. Modelling taint
 * as a boolean would wrongly clear this.
 */

global $wpdb;

$slug = esc_html($_GET['slug']);

$wpdb->query("SELECT * FROM {$wpdb->prefix}acme_items WHERE slug = '{$slug}'"); // wp-taint-expect wp.sqli.wpdb-query sql

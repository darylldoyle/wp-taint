<?php

/**
 * A fully literal query. Nothing to report.
 */

global $wpdb;

$wpdb->query('DELETE FROM wp_acme_log WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)');

<?php

/**
 * An integer cast clears sql taint along with everything else.
 */

global $wpdb;

$id = absint($_GET['id']);

$wpdb->query("DELETE FROM wp_acme_log WHERE id = {$id}");

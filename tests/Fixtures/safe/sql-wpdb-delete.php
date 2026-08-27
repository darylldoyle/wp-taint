<?php

/**
 * wpdb::delete() likewise.
 */

global $wpdb;

$wpdb->delete($wpdb->prefix . 'acme_items', ['id' => $_POST['id']]);

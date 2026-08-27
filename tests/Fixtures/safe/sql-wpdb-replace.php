<?php

/**
 * wpdb::replace() likewise.
 */

global $wpdb;

$wpdb->replace($wpdb->prefix . 'acme_items', ['id' => $_POST['id'], 'title' => $_POST['title']]);

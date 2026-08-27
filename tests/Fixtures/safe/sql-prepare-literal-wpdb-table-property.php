<?php

/**
 * The same for the named table properties wpdb exposes.
 */

global $wpdb;

$email = $_POST['email'];

$user_id = $wpdb->get_var(
    $wpdb->prepare("SELECT ID FROM {$wpdb->users} WHERE user_email = %s", $email)
);

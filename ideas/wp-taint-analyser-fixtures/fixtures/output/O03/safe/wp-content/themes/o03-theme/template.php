<?php

// @wp-taint-source O03
$url = get_user_meta( get_current_user_id(), 'fixture_o03_url', true );
// @wp-taint-sink O03 expect=clean
echo '<a href="' . esc_url( $url ) . '">Profile</a>';

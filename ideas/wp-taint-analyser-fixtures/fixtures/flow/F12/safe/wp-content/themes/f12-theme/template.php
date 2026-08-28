<?php

$subtitle = get_option( 'fixture_f12_subtitle', '' );
// @wp-taint-sink F12 expect=clean
echo '<p class="subtitle">' . esc_html( $subtitle ) . '</p>';

<?php

$subtitle = get_option( 'fixture_f12_subtitle', '' );
// @wp-taint-sink F12 expect=output.unescaped
echo '<p class="subtitle">' . $subtitle . '</p>';

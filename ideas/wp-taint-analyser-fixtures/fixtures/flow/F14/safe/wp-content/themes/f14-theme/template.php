<?php

$banner = fixture_f14_banner();
// @wp-taint-sink F14 expect=clean
echo '<div class="banner">' . esc_html( $banner ) . '</div>';

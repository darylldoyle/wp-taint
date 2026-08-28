<?php

$banner = fixture_f14_banner();
// @wp-taint-sink F14 expect=output.escape_invalidated
echo '<div class="banner">' . $banner . '</div>';

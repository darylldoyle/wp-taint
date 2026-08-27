<?php

/**
 * wp_validate_redirect() clears url taint, so wp_redirect() is safe after it.
 */

$target = wp_validate_redirect($_GET['redirect_to'], home_url());

wp_redirect($target);
exit;

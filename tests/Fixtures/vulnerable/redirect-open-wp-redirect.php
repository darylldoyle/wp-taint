<?php

/**
 * Open redirect. wp_redirect() does not validate the host; wp_safe_redirect()
 * does.
 */

$target = $_GET['redirect_to'];

wp_redirect($target); // wp-taint-expect wp.redirect.open-redirect url
exit;

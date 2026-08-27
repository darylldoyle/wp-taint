<?php

/**
 * wp_safe_redirect() validates the host against the allowed list, so it is not
 * an open redirect sink.
 */

wp_safe_redirect($_GET['redirect_to']);
exit;

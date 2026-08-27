<?php

/**
 * esc_url_raw() is for database storage and redirects. It does not escape
 * for HTML, so this is still XSS.
 */

$url = esc_url_raw($_GET['redirect_to']);

echo '<a href="' . $url . '">Continue</a>'; // wp-taint-expect wp.xss.unescaped-output html

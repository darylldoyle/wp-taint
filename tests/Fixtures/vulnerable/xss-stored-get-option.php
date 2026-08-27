<?php

/**
 * Stored XSS via an option written by a lower-privileged user.
 */

echo '<div class="banner">' . get_option('acme_banner_html') . '</div>'; // wp-taint-expect wp.xss.unescaped-output html

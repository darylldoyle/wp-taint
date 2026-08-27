<?php

/**
 * Stored XSS via post meta. Second-order taint accounts for most of the
 * WordPress CVE population, so the stored sources are on by default.
 */

$subtitle = get_post_meta(get_the_ID(), 'event_subtitle', true);

echo '<h3>' . $subtitle . '</h3>'; // wp-taint-expect wp.xss.unescaped-output html

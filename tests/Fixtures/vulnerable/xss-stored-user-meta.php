<?php

/**
 * Stored XSS via user meta.
 */

$tagline = get_user_meta(get_current_user_id(), 'acme_tagline', true);

printf('<p class="tagline">%s</p>', $tagline); // wp-taint-expect wp.xss.unescaped-output html

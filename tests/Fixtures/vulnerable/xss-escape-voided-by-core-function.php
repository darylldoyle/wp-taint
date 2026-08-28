<?php

/**
 * The filter is not visible here. `wp_trim_words()` runs `wp_trim_words`
 * internally and returns the result, so a plugin decides what comes back and
 * the escaping done before the call is void by the time it is printed.
 *
 * 629 core functions return a filtered value; the list is generated from a
 * WordPress checkout by tools/generate-filterable-catalogue.php rather than
 * guessed at from names.
 */

function acme_render_excerpt()
{
    $excerpt = esc_html($_GET['excerpt']);

    echo wp_trim_words($excerpt, 20); // wp-taint-expect wp.xss.escape-voided escape_voided
}

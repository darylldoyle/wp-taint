<?php

/**
 * `%2$s` maps to its named argument, deterministically.
 *
 * Positional specifiers used to end the analysis; there is nothing to guess —
 * `%2$s` is the second variadic argument, and here it is esc_attr() landing in
 * an href.
 */

function acme_positional($id, $url)
{
    printf('<a id="%1$s" href="%2$s">x</a>', esc_attr($id), esc_attr($url)); // wp-taint-expect wp.xss.wrong-context-escape html
}

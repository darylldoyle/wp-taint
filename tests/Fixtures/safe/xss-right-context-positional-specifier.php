<?php

/**
 * Positional specifiers with the right escaper in each hole.
 *
 * The counterpart to the vulnerable positional fixture: mapping `%n$s` to its
 * argument must credit the correct pairing, not just accuse the wrong one.
 */

function acme_positional_ok($id, $url)
{
    printf('<a id="%1$s" href="%2$s">x</a>', esc_attr($id), esc_url($url));
}

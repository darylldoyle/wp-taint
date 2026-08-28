<?php

/**
 * The same two calls in the order that holds: let the core function and its
 * filter run, then escape the result at the point of output.
 */

function acme_render_excerpt_safe()
{
    echo esc_html(wp_trim_words($_GET['excerpt'], 20));
}

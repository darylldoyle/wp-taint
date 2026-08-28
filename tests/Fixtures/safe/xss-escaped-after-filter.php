<?php

/**
 * The same two operations in the order that holds: let every filter run, then
 * escape what comes back, at the point of output.
 */

function acme_render_title_safe()
{
    echo esc_html(apply_filters('acme_title', $_GET['title']));
}

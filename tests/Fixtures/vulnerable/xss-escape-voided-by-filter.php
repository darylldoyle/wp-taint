<?php

/**
 * Escaping is called *late* escaping because it has to be the last thing that
 * happens to a value. Here it is not: any plugin on the site may hook
 * `acme_title` and return whatever it likes, and this code prints the result.
 *
 * Invisible to a plain taint model, which sees the escaper clear the taint and
 * nothing put it back.
 */

function acme_render_title()
{
    $title = esc_html($_GET['title']);

    echo apply_filters('acme_title', $title); // wp-taint-expect wp.xss.escape-voided escape_voided
}

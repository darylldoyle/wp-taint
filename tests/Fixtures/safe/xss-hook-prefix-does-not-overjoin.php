<?php

/**
 * Prefix joining stays inside its namespace.
 *
 * The dispatch's head is `acme_render_`; the registration is on
 * `acme_totally_other`, which does not start with it, so no join happens and
 * the escaped callback is never handed the raw payload. And a head shorter
 * than the minimum joins nothing at all.
 */

add_action('acme_totally_other', function ($value) {
    echo esc_html($value);
});

function acme_dispatch($section)
{
    do_action("acme_render_{$section}", $_GET['content']);
}

function acme_too_wide($x)
{
    do_action("a_{$x}", $_GET['nope']);
}

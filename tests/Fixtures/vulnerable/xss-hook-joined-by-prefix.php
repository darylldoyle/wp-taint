<?php

/**
 * Dynamic hook names joined to their literal counterparts by folded head.
 *
 * `do_action( "acme_render_{$section}" )` can run whatever is registered on
 * any literal hook starting with `acme_render_`, and a registration on
 * `"acme_save_{$type}"` can be run by a literal `do_action( 'acme_save_post' )`.
 * Both joins carry the dispatch's arguments into the callbacks. A head shorter
 * than four characters joins nothing — that wide a match is a guess.
 */

add_action('acme_render_header', function ($value) {
    echo $value; // wp-taint-expect wp.xss.unescaped-output html
});

function acme_dispatch($section)
{
    do_action("acme_render_{$section}", $_GET['content']);
}

function acme_register($type)
{
    add_action("acme_save_{$type}", function ($v) {
        echo $v; // wp-taint-expect wp.xss.unescaped-output html
    });
}

function acme_fire()
{
    do_action('acme_save_post', $_GET['payload']);
}

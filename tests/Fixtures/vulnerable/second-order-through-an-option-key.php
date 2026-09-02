<?php

/**
 * Second-order flows through a named option key, both ends visible.
 *
 * The write puts request data under 'acme_banner'; the read of the same key
 * carries that write's taint and trace on top of the stored baseline. The
 * include is the shape only per-key tracking can prove: stored sources carry
 * no `path` taint by design, so `include get_option( … )` was silent unless
 * the scan watched the path go in. The helper variant stores through a
 * wrapper, carried by the same summary pipeline property writes use.
 */

function acme_save()
{
    update_option('acme_banner', wp_unslash($_POST['banner']));
}

function acme_show()
{
    echo get_option('acme_banner'); // wp-taint-expect wp.xss.unescaped-output html
}

function acme_save_template()
{
    update_option('acme_template', wp_unslash($_POST['tpl']));
}

function acme_render_template()
{
    include get_option('acme_template'); // wp-taint-expect wp.lfi.dynamic-include path
}

function acme_store($value)
{
    update_option('acme_relayed', $value);
}

function acme_relay()
{
    acme_store($_GET['x']);
}

function acme_show_relayed()
{
    echo get_option('acme_relayed'); // wp-taint-expect wp.xss.unescaped-output html
}

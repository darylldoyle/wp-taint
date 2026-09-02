<?php

/**
 * The same function declared twice, and only the second copy is dangerous.
 *
 * First-in-file-order used to speak for both, and here that is the escaping
 * copy. The caller now sees the union of both bodies — a parameter is only
 * credited as cleared when every body clears it.
 */

if (! function_exists('acme_render')) {
    function acme_render($v)
    {
        return esc_html($v);
    }
}

if (defined('ACME_LEGACY')) {
    function acme_render($v)
    {
        return $v;
    }
}

echo acme_render($_GET['x']); // wp-taint-expect wp.xss.unescaped-output html

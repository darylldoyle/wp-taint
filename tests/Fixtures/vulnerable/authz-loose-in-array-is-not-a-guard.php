<?php

/**
 * A loose in_array() against numbers is not a constraint. Before PHP 8,
 * `'1<script>' == 1` holds, so the value reaching output is still whatever
 * was asked for. Against strings that are not numeric, a loose comparison
 * stretches nothing, and the check counts as a strict one does.
 */

function acme_render_loose()
{
    $mode = $_GET['mode'];

    if (! in_array($mode, array(1, 2))) {
        return;
    }

    echo $mode; // wp-taint-expect wp.xss.unescaped-output html
}

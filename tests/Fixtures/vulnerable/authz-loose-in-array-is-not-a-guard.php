<?php

/**
 * Loose in_array() is not a constraint: type juggling smuggles values past it,
 * so the value reaching output is still whatever was asked for. Only the strict
 * comparison counts as a guard.
 */

function acme_render_loose()
{
    $mode = $_GET['mode'];

    if (! in_array($mode, array('grid', 'list'))) {
        return;
    }

    echo $mode; // wp-taint-expect wp.xss.unescaped-output html
}

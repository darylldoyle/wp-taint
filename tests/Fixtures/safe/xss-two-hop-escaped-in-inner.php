<?php

/**
 * Two function boundaries with the escaping applied in the innermost one.
 */

function wrap_span($text)
{
    return '<span>' . esc_html($text) . '</span>';
}

function build_row($value)
{
    return '<td>' . wrap_span($value) . '</td>';
}

echo build_row($_GET['cell']);

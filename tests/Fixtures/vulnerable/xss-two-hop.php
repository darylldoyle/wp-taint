<?php

/**
 * Reflected XSS crossing two function boundaries.
 */

function wrap_span($text)
{
    return '<span>' . $text . '</span>';
}

function build_row($value)
{
    return '<td>' . wrap_span($value) . '</td>';
}

$cell = $_GET['cell'];

echo build_row($cell); // wp-taint-expect wp.xss.unescaped-output html

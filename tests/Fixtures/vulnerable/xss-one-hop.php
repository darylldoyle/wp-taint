<?php

/**
 * Reflected XSS crossing one function boundary.
 *
 * The taint enters render_heading() as parameter 0 and returns unescaped.
 */

function render_heading($label)
{
    return '<h2>' . $label . '</h2>';
}

$filter = $_GET['report_filter'];

echo render_heading($filter); // wp-taint-expect wp.xss.unescaped-output html

<?php

/**
 * Interprocedural sanitisation. The helper escapes its parameter before
 * returning, so the value reaching echo is clean.
 *
 * This is the classic false positive source: an engine without function
 * summaries flags it.
 */

function render_heading($label)
{
    return '<h2>' . esc_html($label) . '</h2>';
}

$filter = $_GET['report_filter'];

echo render_heading($filter);

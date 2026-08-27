<?php

/**
 * Escaping applied at the call site rather than inside the callee.
 */

function render_heading($label)
{
    return '<h2>' . $label . '</h2>';
}

echo render_heading(esc_html($_GET['report_filter']));

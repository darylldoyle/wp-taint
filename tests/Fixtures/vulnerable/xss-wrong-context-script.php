<?php

/**
 * esc_html() inside a <script> block. HTML entities mean nothing to the
 * JavaScript parser, so `";alert(1);//` closes the string and runs.
 */

function acme_render_config($value)
{
    echo '<script>var x = "' . esc_html($value) . '";</script>'; // wp-taint-expect wp.xss.wrong-context-escape authz
}

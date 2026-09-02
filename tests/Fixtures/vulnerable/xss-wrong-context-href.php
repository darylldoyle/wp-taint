<?php

/**
 * An escaper is present and it is the wrong one. esc_attr() escapes quotes and
 * angle brackets; a `javascript:` scheme contains neither, so it survives and
 * runs. A check that only asks whether an escaper was called reports nothing.
 */

function acme_render_link($url)
{
    printf('<a href="%s">Go</a>', esc_attr($url)); // wp-taint-expect wp.xss.wrong-context-escape html
}

<?php

/**
 * The same three contexts with the escaper each one actually needs.
 */

function acme_render_all($url, $value)
{
    printf('<a href="%s">Go</a>', esc_url($url));
    echo '<script>var x = ' . wp_json_encode($value) . ';</script>';
    printf('<div class="%s"></div>', esc_attr($value));
}

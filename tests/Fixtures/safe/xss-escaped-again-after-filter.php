<?php

/**
 * Escaped, filtered, then escaped again at the point of output. The filter may
 * return anything it likes and wp_kses_post() still runs on the result, so the
 * order holds. Taken from Cookie Law Info, where the rule reported it until
 * escaping was made to clear an earlier voiding.
 */

function acme_render_overview($title)
{
    echo wp_kses_post(apply_filters('acme_overview_title', esc_html($title)));
}

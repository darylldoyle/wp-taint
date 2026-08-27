<?php

/**
 * Reflected XSS from a REST request parameter.
 */

function acme_render_preview(WP_REST_Request $request)
{
    $body = $request->get_param('body');

    echo '<div class="preview">' . $body . '</div>'; // wp-taint-expect wp.xss.unescaped-output html
}

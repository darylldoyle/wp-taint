<?php

/**
 * REST parameter escaped before output.
 */

function acme_render_preview(WP_REST_Request $request)
{
    echo '<div class="preview">' . wp_kses_post($request->get_param('body')) . '</div>';
}

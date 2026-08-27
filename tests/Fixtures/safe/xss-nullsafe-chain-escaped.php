<?php

/**
 * The same nullsafe chain with escaping applied.
 */

function acme_render(?WP_REST_Request $request): void
{
    echo '<div>' . esc_html((string) $request?->get_param('body')) . '</div>';
}

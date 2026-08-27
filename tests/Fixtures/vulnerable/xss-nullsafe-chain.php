<?php

/**
 * Taint through a nullsafe method call, which php-cfg cannot parse and
 * CompatibilityVisitor lowers to its plain equivalent.
 */

function acme_render(?WP_REST_Request $request): void
{
    $body = $request?->get_param('body');

    echo '<div>' . $body . '</div>'; // wp-taint-expect wp.xss.unescaped-output html
}

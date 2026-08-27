<?php

/**
 * A regular action hook with no capability check is not an AJAX endpoint and
 * must not be reported by the AJAX rule.
 */

add_action('init', 'acme_register_post_types');

function acme_register_post_types()
{
    register_post_type('acme_item', ['public' => true]);
}

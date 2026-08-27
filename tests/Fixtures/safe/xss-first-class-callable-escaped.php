<?php

/**
 * The same shape with escaping inside the helper.
 */

function acme_wrap($value)
{
    return '<span>' . esc_html($value) . '</span>';
}

$callback = acme_wrap(...);

echo acme_wrap($_GET['tag']);

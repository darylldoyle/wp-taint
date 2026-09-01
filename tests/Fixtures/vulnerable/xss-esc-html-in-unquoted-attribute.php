<?php

/**
 * esc_html() is safe in a *quoted* attribute but not an unquoted one: it does
 * not encode the space that ends an unquoted value, so `x onmouseover=alert(1)`
 * survives. Treating esc_html() as attribute-safe must not extend to this shape.
 */

function acme_render($value)
{
    printf('<div data-v=%s></div>', esc_html($value)); // wp-taint-expect wp.xss.wrong-context-escape html
}

acme_render($_GET['v']);

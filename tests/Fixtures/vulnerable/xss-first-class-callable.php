<?php

/**
 * A first-class callable alongside a normal call to the same helper.
 *
 * CompatibilityVisitor rewrites `acme_wrap(...)` to the callable string
 * `'acme_wrap'`, which is what the same code would have said before PHP 8.1.
 * Without that rewrite php-cfg refuses the whole file, and the real finding
 * below disappears with it.
 */

function acme_wrap($value)
{
    return '<span>' . $value . '</span>';
}

$callback = acme_wrap(...);

$rendered = acme_wrap($_GET['tag']);

echo $rendered; // wp-taint-expect wp.xss.unescaped-output html

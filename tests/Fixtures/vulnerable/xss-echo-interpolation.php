<?php

/**
 * Reflected XSS through double-quoted string interpolation.
 *
 * php-cfg lowers this to Expr_ConcatList, not a Concat chain.
 */

$term = $_GET['s'];

echo "<h2>Results for {$term}</h2>"; // wp-taint-expect wp.xss.unescaped-output html

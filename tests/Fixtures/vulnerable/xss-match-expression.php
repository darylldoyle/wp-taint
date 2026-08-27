<?php

/**
 * Taint flowing through a match expression.
 *
 * php-cfg cannot parse `match`, so CompatibilityVisitor lowers it to a ternary
 * chain before the CFG is built. This fixture is the regression test for that.
 */

$mode = $_GET['mode'];

$label = match ($mode) {
    'draft' => 'Draft',
    'live' => $_GET['live_label'],
    default => $mode,
};

echo '<h2>' . $label . '</h2>'; // wp-taint-expect wp.xss.unescaped-output html

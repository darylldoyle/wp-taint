<?php

/**
 * Taint entering a loop-carried variable. Exercises phi node handling at the
 * loop header.
 */

$rows = '';

foreach ($_GET['items'] as $item) {
    $rows .= '<li>' . $item . '</li>';
}

echo '<ul>' . $rows . '</ul>'; // wp-taint-expect wp.xss.unescaped-output html

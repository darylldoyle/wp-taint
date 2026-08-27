<?php

/**
 * Taint written into an array and read back out. Array taint is
 * over-approximated to the whole array; see KNOWN_LIMITATIONS.md.
 */

$context = [];
$context['title'] = $_GET['title'];

echo '<h1>' . $context['title'] . '</h1>'; // wp-taint-expect wp.xss.unescaped-output html

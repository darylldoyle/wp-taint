<?php

/**
 * wp_unslash() removes slashes. It does not escape anything.
 *
 * This is the single most common misunderstanding in WordPress code review,
 * so it gets its own fixture.
 */

$search = wp_unslash($_GET['s']);

echo '<h1>' . $search . '</h1>'; // wp-taint-expect wp.xss.unescaped-output html

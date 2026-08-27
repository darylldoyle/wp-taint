<?php

/**
 * Reflected XSS via vprintf with an argument array.
 */

$args = [$_GET['first'], $_GET['second']];

vprintf('<p>%s %s</p>', $args); // wp-taint-expect wp.xss.unescaped-output html

<?php

/**
 * Reflected XSS reaching echo through string concatenation.
 */

$name = $_GET['name'];

echo '<p>Hello ' . $name . '</p>'; // wp-taint-expect wp.xss.unescaped-output html

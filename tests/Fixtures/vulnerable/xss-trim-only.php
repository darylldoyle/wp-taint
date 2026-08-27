<?php

/**
 * trim() propagates taint untouched.
 */

$slug = trim($_GET['slug']);

echo "<span>{$slug}</span>"; // wp-taint-expect wp.xss.unescaped-output html

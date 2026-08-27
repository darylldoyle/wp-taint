<?php

/**
 * Reflected XSS through a closure invoked immediately.
 */

$render = static function ($text) {
    return '<em>' . $text . '</em>';
};

echo $render($_GET['emphasis']); // wp-taint-expect wp.xss.unescaped-output html

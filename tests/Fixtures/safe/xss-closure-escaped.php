<?php

/**
 * Closure that escapes its parameter.
 */

$render = static function ($text) {
    return '<em>' . esc_html($text) . '</em>';
};

echo $render($_GET['emphasis']);

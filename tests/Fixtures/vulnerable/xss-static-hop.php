<?php

/**
 * Reflected XSS crossing a static method boundary.
 */

class Formatter
{
    public static function badge($text)
    {
        return '<span class="badge">' . $text . '</span>';
    }
}

echo Formatter::badge($_GET['tag']); // wp-taint-expect wp.xss.unescaped-output html

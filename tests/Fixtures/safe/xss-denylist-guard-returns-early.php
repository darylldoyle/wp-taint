<?php

/**
 * WordPress core's `wp_specialchars()` opens with this, and dozens of plugins
 * vendor a copy of it. Failing to match a class of dangerous characters proves
 * none of them is present, so the early return hands back a value that needs no
 * escaping — and the escape below covers everything else.
 *
 * Getting this wrong reported every plugin carrying a copy of core's fast path,
 * Duplicator's installer among them.
 */

class Acme_Escaper
{
    public static function specialchars($string)
    {
        if (! preg_match('/[&<>"\']/', $string)) {
            return $string;
        }

        return htmlspecialchars($string, ENT_QUOTES);
    }
}

echo Acme_Escaper::specialchars($_GET['value']);

<?php

/**
 * $_SERVER['REQUEST_URI'] is attacker-controlled. Most other $_SERVER keys
 * are not, and treating the whole superglobal as tainted is unmanageable.
 */

echo '<form action="' . $_SERVER['REQUEST_URI'] . '">'; // wp-taint-expect wp.xss.unescaped-output html

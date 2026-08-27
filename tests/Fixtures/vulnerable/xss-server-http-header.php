<?php

/**
 * Any HTTP_* key in $_SERVER comes straight from a request header.
 */

echo '<p>You came from ' . $_SERVER['HTTP_REFERER'] . '</p>'; // wp-taint-expect wp.xss.unescaped-output html

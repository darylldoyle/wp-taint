<?php

/**
 * Reflected XSS: a superglobal echoed with no escaping at all.
 */

echo $_GET['message']; // wp-taint-expect wp.xss.unescaped-output html

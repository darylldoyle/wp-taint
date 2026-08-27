<?php

/**
 * Reflected XSS via print.
 */

print $_POST['comment']; // wp-taint-expect wp.xss.unescaped-output html

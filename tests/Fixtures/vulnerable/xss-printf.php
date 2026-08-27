<?php

/**
 * Reflected XSS via printf, which writes directly to output.
 */

printf('<div class="notice">%s</div>', $_GET['notice']); // wp-taint-expect wp.xss.unescaped-output html

<?php

/**
 * wp_get_referer() reads the Referer header.
 */

echo '<input type="hidden" name="back" value="' . wp_get_referer() . '">'; // wp-taint-expect wp.xss.unescaped-output html

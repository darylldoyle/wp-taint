<?php

/**
 * sanitize_html_class() is the right escaper for a class attribute value.
 */

echo '<div class="' . sanitize_html_class($_GET['variant']) . '"></div>';

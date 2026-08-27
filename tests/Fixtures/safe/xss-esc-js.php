<?php

/**
 * esc_js() for a value inside an inline script string.
 */

echo '<script>var label = "' . esc_js($_GET['label']) . '";</script>';

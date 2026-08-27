<?php

/**
 * sanitize_key() restricts to lowercase alphanumerics, dashes and underscores.
 */

$key = sanitize_key($_GET['tab']);

echo '<div class="tab-' . $key . '"></div>';

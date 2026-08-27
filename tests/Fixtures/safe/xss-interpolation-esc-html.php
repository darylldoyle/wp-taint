<?php

/**
 * Escaped before interpolation.
 */

$term = esc_html($_GET['s']);

echo "<h2>Results for {$term}</h2>";

<?php

/**
 * Escaped before concatenation.
 */

$name = esc_html($_GET['name']);

echo '<p>Hello ' . $name . '</p>';

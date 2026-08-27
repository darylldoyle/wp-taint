<?php

/**
 * The same match expression with every arm escaped, and the default arm a
 * literal rather than the tainted subject.
 */

$mode = $_GET['mode'];

$label = match ($mode) {
    'draft' => 'Draft',
    'live' => esc_html($_GET['live_label']),
    default => 'Unknown',
};

echo '<h2>' . $label . '</h2>';

<?php

/**
 * The user input selects from an allowlist rather than naming the file. The
 * value reaching include is a literal from the map.
 */

$templates = [
    'list' => 'list.php',
    'grid' => 'grid.php',
];

$requested = sanitize_key($_GET['template']);

if (isset($templates[$requested])) {
    include ACME_PLUGIN_DIR . '/templates/' . $templates[$requested];
}

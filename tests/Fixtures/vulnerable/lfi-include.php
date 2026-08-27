<?php

/**
 * Local file inclusion through include with user-controlled path.
 */

$template = $_GET['template'];

include ACME_PLUGIN_DIR . '/templates/' . $template . '.php'; // wp-taint-expect wp.lfi.dynamic-include path

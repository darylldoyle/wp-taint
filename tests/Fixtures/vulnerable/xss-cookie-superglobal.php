<?php

/**
 * $_COOKIE is attacker-controlled.
 */

$last_view = $_COOKIE['wp_last_view'];

echo "<div data-view=\"{$last_view}\"></div>"; // wp-taint-expect wp.xss.unescaped-output html

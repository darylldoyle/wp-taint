<?php

/**
 * get_query_var() returns request-derived data.
 */

$view = get_query_var('acme_view');

echo "<body class=\"view-{$view}\">"; // wp-taint-expect wp.xss.unescaped-output html

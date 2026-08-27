<?php

/**
 * Query var escaped for an attribute.
 */

echo '<body class="' . esc_attr(get_query_var('acme_view')) . '">';

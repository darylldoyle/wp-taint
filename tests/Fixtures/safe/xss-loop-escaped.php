<?php

/**
 * Escaping inside a loop body. The loop-carried phi merges clean values only.
 */

$rows = '';

foreach ((array) $_GET['items'] as $item) {
    $rows .= '<li>' . esc_html($item) . '</li>';
}

echo '<ul>' . $rows . '</ul>';

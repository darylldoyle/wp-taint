<?php

/**
 * Only one branch escapes. The phi node unions both incoming taint sets, so
 * the merged value is still tainted.
 */

$note = $_GET['note'];

if (is_admin()) {
    $note = esc_html($note);
}

echo '<p>' . $note . '</p>'; // wp-taint-expect wp.xss.unescaped-output html

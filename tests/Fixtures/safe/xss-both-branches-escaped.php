<?php

/**
 * Both branches escape, with different escapers. The phi node unions two clean
 * sets, so the merged value is clean.
 */

$note = $_GET['note'];

if (is_admin()) {
    $note = esc_html($note);
} else {
    $note = wp_kses_post($note);
}

echo '<p>' . $note . '</p>';

<?php

/**
 * The correct wp_unslash() idiom: unslash to undo magic quotes, then apply a
 * real escaper. wp_unslash() itself clears nothing, so the escaper is what
 * makes this safe.
 */

$search = sanitize_text_field(wp_unslash($_GET['s']));

echo '<h1>' . esc_html($search) . '</h1>';

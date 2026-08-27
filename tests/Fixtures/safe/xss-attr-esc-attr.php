<?php

/**
 * Attribute context escaped with esc_attr, which clears both html and
 * html_attr taint.
 */

$view = $_GET['view'];

echo '<div data-view="' . esc_attr($view) . '"></div>';

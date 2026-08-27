<?php

/**
 * esc_url() is the correct escaper for a URL in an href attribute. It clears
 * html, html_attr and url.
 */

echo '<a href="' . esc_url($_GET['redirect_to']) . '">Continue</a>';

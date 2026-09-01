<?php

/**
 * esc_html() runs _wp_specialchars() with ENT_QUOTES, so it encodes both quote
 * characters. A value it escapes cannot break out of a quoted attribute, so the
 * wrong-context rule must not demand esc_attr() here.
 */

printf('<div data-label="%s"></div>', esc_html($_GET['label']));

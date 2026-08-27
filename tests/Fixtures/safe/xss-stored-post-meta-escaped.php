<?php

/**
 * Stored value, correctly escaped on output.
 */

$subtitle = get_post_meta(get_the_ID(), 'event_subtitle', true);

echo '<h3>' . esc_html($subtitle) . '</h3>';

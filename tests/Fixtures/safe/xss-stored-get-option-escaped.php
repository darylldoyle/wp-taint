<?php

/**
 * Option value passed through wp_kses_post, which is the right call when the
 * option is intended to hold markup.
 */

echo '<div class="banner">' . wp_kses_post(get_option('acme_banner_html')) . '</div>';

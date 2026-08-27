<?php

/**
 * printf with escaping applied to the argument.
 */

printf('<div class="notice">%s</div>', esc_html($_GET['notice']));

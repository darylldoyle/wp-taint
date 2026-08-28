<?php

/**
 * Only a hook voids escaping. trim() is not something a third party can
 * substitute, so the escaper's guarantee survives it.
 */

function acme_render_trimmed()
{
    echo trim(esc_html($_GET['title']));
}

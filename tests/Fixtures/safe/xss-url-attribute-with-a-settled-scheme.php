<?php

/**
 * URL rules apply only while the hole can still choose the scheme.
 *
 * `href="#…"` is a fragment and `href="/…"` is a path whatever follows, so
 * esc_attr() is the right escaper there — Contact Form 7 writes the fragment
 * shape for its validation-error anchors. And esc_url() in an *unquoted*
 * attribute is safe too: its character filter strips the space and `>` that
 * could end the value.
 */

function acme_error_anchor($id, $label)
{
    printf('<a href="#%1$s">%2$s</a>', esc_attr($id), esc_html($label));
}

function acme_path_link($page)
{
    printf('<a href="/admin/%s">open</a>', esc_attr($page));
}

function acme_unquoted_update_link()
{
    echo '<a class="button" href=' . esc_url(admin_url('plugins.php')) . '>Update Now</a>';
}

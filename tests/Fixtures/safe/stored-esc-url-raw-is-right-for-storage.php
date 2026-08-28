<?php

/**
 * WordPress asks for two different things: sanitise on input, escape on output.
 * esc_url_raw() is exactly the right sanitizer for storing a URL and exactly
 * the wrong one for printing it, so it settles the storage obligation and not
 * the output one.
 *
 * Sharing one taint kind between the two questions reported this line, and a
 * third-party suite labels it safe.
 */

// wp-taint-options stored-taint-writes
function acme_save_endpoint()
{
    update_option('acme_endpoint', esc_url_raw(wp_unslash($_POST['endpoint'])));
}

<?php

/**
 * wp_unslash() undoes magic quotes. It cleans nothing, and mistaking it for a
 * sanitizer is the most common misreading in WordPress code review — which is
 * why it is a propagator here and why it does not settle the storage
 * obligation.
 */

// wp-taint-options stored-taint-writes
function acme_save_note()
{
    update_post_meta(42, '_acme_note', wp_unslash($_POST['note'])); // wp-taint-expect wp.stored.untrusted-write storage
}

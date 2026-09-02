<?php

/**
 * The safe counterpart: the captured parameter is escaped inside the closure.
 *
 * Publishing the caller's taint into the capture must still credit what the
 * closure body does with it.
 */

function acme_notice_safe($msg)
{
    add_action('admin_notices', function () use ($msg) {
        echo esc_html($msg);
    });
}

acme_notice_safe($_GET['ok']);

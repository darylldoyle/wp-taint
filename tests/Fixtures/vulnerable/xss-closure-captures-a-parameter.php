<?php

/**
 * A closure capturing the enclosing function's own parameter.
 *
 * The closure's scope is published by the run that seeds nothing, where a
 * parameter is clean — so what the caller actually passed never reached the
 * body. The probe run now records "parameter reaches capture $msg" in the
 * summary and the call site publishes the caller's taint, the same split the
 * property map uses. The second function proves it crosses a helper: the
 * parameter passes through acme_relay() before being captured.
 */

function acme_notice($msg)
{
    add_action('admin_notices', function () use ($msg) {
        echo $msg; // wp-taint-expect wp.xss.unescaped-output html
    });
}

acme_notice($_GET['m']);

function acme_register_deep($text)
{
    add_action('wp_footer', function () use ($text) {
        echo $text; // wp-taint-expect wp.xss.unescaped-output html
    });
}

function acme_relay($value)
{
    acme_register_deep($value);
}

acme_relay($_GET['deep']);

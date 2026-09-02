<?php

/**
 * The context lives in a variable bound once, a line above its use.
 *
 * Folding the binding recovers the literal context, so the href/esc_attr
 * mismatch is judged the same as if it were written inline — in both the
 * printf spelling and the concat-then-echo one.
 */

function acme_link($url)
{
    $anchor_tpl = '<a href="%s">go</a>';
    printf($anchor_tpl, esc_attr($url)); // wp-taint-expect wp.xss.wrong-context-escape html
}

function acme_link_concat($url)
{
    $html = '<a href="' . esc_attr($url) . '">go</a>';
    echo $html; // wp-taint-expect wp.xss.wrong-context-escape html
}

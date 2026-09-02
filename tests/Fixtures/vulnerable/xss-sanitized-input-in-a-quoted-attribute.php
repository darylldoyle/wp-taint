<?php

/**
 * sanitize_text_field() strips tags; it does not touch quotes.
 *
 * The value that survives it is nothing in HTML text and a breakout in a
 * quoted attribute: `" onmouseover=alert(1) x="` ends the value and starts
 * new attributes. Sanitising at input is about storing clean data — where the
 * value lands still decides the escaper. The kses variant is the same shape
 * one step up: markup is allowed through, and so are the quotes in it.
 */

function acme_search_box()
{
    $term = sanitize_text_field(wp_unslash($_GET['s']));

    echo '<input type="text" name="s" value="' . $term . '">'; // wp-taint-expect wp.xss.unescaped-attribute html_attr
}

function acme_tooltip()
{
    echo '<span title="' . wp_kses_post(wp_unslash($_GET['tip'])) . '">?</span>'; // wp-taint-expect wp.xss.unescaped-attribute html_attr
}

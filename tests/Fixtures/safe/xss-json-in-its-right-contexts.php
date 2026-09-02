<?php

/**
 * The three correct spellings for JSON reaching markup.
 *
 * Inside a <script> block json_encode() is the right escaper; in an attribute
 * it needs esc_attr() around it; in an event handler esc_js() entity-encodes
 * the quotes json_encode() has to emit. A bare echo with no markup in the
 * statement is also left alone — the statement shows no context to judge.
 */

function acme_script($settings)
{
    echo '<script>var acmeConfig = ' . wp_json_encode($settings) . ';</script>';
}

function acme_attr($settings)
{
    echo '<div data-config="' . esc_attr(wp_json_encode($settings)) . '"></div>';
}

function acme_handler($label)
{
    echo '<button onclick="acmeRun(\'' . esc_js($label) . '\')">go</button>';
}

function acme_bare($settings)
{
    echo wp_json_encode($settings);
}

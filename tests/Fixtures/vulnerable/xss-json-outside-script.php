<?php

/**
 * json_encode() escapes for a JavaScript value position and nothing else.
 *
 * `<` survives it, so JSON in HTML text is live markup; the JSON's own quotes
 * end a quoted attribute; and both together end an event handler before any
 * JavaScript runs. Only a <script> block is its context — see the safe
 * counterpart.
 */

function acme_config_div($settings)
{
    echo '<div class="acme-config">' . wp_json_encode($settings) . '</div>'; // wp-taint-expect wp.xss.wrong-context-escape html
}

function acme_config_attr($settings)
{
    echo '<div data-config="' . wp_json_encode($settings) . '"></div>'; // wp-taint-expect wp.xss.wrong-context-escape html
}

function acme_config_handler($settings)
{
    printf('<button onclick="acmeRun(%s)">go</button>', wp_json_encode($settings)); // wp-taint-expect wp.xss.wrong-context-escape html
}

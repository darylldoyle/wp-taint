<?php

/**
 * The counterparts that must stay quiet.
 *
 * sanitize_text_field() output in HTML text has no tags left to inject;
 * esc_attr() makes the attribute safe wherever the value came from; and
 * esc_html() runs ENT_QUOTES, so its output cannot end a quoted attribute
 * either — accusing it there was the false-positive class the structural
 * rule already retired.
 */

function acme_heading()
{
    $term = sanitize_text_field(wp_unslash($_GET['s']));

    echo '<h2>Results for ' . $term . '</h2>';
}

function acme_search_box_escaped()
{
    $term = sanitize_text_field(wp_unslash($_GET['s']));

    echo '<input type="text" name="s" value="' . esc_attr($term) . '">';
}

function acme_data_attribute()
{
    echo '<div data-label="' . esc_html(wp_unslash($_GET['v'])) . '"></div>';
}

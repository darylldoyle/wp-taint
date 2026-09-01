<?php

/**
 * A non-literal prepare() format string is the injection surface and is reported
 * as such. Its placeholder arguments are a separate matter: prepare() still
 * substitutes and escapes every %s/%d/%i argument whether or not the template
 * was literal, so a request value bound to a placeholder does not reach the
 * query as raw SQL. Only the format string is reported here — the %s-bound $url
 * must not raise a second, unprepared-query finding on the outer query().
 */

function acme_lookup($table)
{
    global $wpdb;

    $url = $_GET['u'];

    return $wpdb->query($wpdb->prepare("SELECT id FROM {$table} WHERE url = %s", $url)); // wp-taint-expect wp.sqli.prepare-non-literal sql
}

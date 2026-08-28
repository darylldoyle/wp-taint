<?php

/**
 * A table name the plugin builds for itself is not request data, so an
 * unquoted interpolation of it is the ordinary idiom rather than a finding.
 */

class Acme_Table
{
    private $table;

    public function __construct()
    {
        global $wpdb;

        $this->table = $wpdb->prefix . 'acme_log';
    }

    public function count_rows()
    {
        global $wpdb;

        return $wpdb->get_var("SELECT COUNT(*) FROM {$this->table}");
    }
}

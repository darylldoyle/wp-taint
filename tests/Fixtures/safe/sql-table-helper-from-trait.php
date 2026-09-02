<?php

/**
 * A table-name helper brought in by a trait, called through a class that uses
 * it — and through a subclass of that class, which exercises the full lookup
 * order: own methods, then traits, then the parent and its traits.
 */

trait Acme_Has_Table
{
    public static function table_name()
    {
        global $wpdb;

        return $wpdb->prefix . 'acme_rows';
    }
}

class Acme_Repository
{
    use Acme_Has_Table;
}

class Acme_Special_Repository extends Acme_Repository
{
}

function acme_rows()
{
    global $wpdb;

    $table = Acme_Repository::table_name();

    return $wpdb->get_results("SELECT * FROM {$table}");
}

function acme_special_rows()
{
    global $wpdb;

    $table = Acme_Special_Repository::table_name();

    return $wpdb->get_results("SELECT * FROM {$table}");
}

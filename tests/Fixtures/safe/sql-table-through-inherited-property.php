<?php

/**
 * A property declared on the base class, navigated through the subclass.
 *
 * `protected Acme_DB $db` lives on the parent; the read is in the child. The
 * property-type lookup follows the hierarchy, so `$this->db` resolves to
 * Acme_DB, the `table()` call resolves to its body, and the `$wpdb->prefix`
 * value it returns is accounted for. The untyped `$table` written in the
 * parent's constructor is the same shape one level simpler.
 */

class Acme_DB
{
    public function table()
    {
        global $wpdb;

        return $wpdb->prefix . 'acme';
    }
}

class Acme_Plugin_Base
{
    protected Acme_DB $db;
    protected $table;

    public function __construct()
    {
        global $wpdb;

        $this->db = new Acme_DB();
        $this->table = $wpdb->prefix . 'acme_rows';
    }
}

class Acme_Plugin extends Acme_Plugin_Base
{
    public function via_typed_property()
    {
        global $wpdb;

        $t = $this->db->table();

        return $wpdb->get_results("SELECT * FROM {$t}");
    }

    public function via_tracked_property()
    {
        global $wpdb;

        return $wpdb->get_results("SELECT * FROM {$this->table}");
    }
}

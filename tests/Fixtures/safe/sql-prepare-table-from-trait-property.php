<?php

/**
 * A table name held on a property, read from a trait method.
 *
 * The write is in the class; the read is in the trait, whose declaring class is
 * the trait as far as the CFG is concerned. Two things had to be true for this
 * to stay quiet: clean property writes have to be recorded at all, and a
 * property the scan cannot find under the reading class has to be checked by
 * name across every class that has one.
 *
 * LiteSpeed Cache produced 57 findings on this shape before both were fixed,
 * and 6 after.
 */

trait Acme_Queries
{
    public function find($md5)
    {
        global $wpdb;

        return $wpdb->get_var(
            $wpdb->prepare('SELECT url FROM `' . $this->table . '` WHERE md5 = %s', $md5)
        );
    }
}

class Acme_Avatar
{
    use Acme_Queries;

    private $table;

    public function __construct()
    {
        global $wpdb;

        $this->table = $wpdb->prefix . 'acme_avatar';
    }
}

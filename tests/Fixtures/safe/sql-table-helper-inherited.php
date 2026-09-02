<?php

/**
 * A table-name helper inherited from a parent class.
 *
 * The Gravity Forms shape: `RGFormsModel extends GFFormsModel`, the helpers
 * live on the parent, and every call is spelled through the subclass. Method
 * lookup walks the `extends` chain, so the call resolves to the parent's body
 * and the value it returns — `$wpdb->prefix` plus a literal — is accounted for.
 */

class Acme_Model_Base
{
    public static function table_name()
    {
        global $wpdb;

        return $wpdb->prefix . 'acme_things';
    }
}

class Acme_Model extends Acme_Model_Base
{
}

function acme_all_things()
{
    global $wpdb;

    $table = Acme_Model::table_name();

    return $wpdb->get_results("SELECT * FROM {$table}");
}

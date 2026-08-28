<?php

/**
 * A fixed fragment anywhere in the name pens the attacker into a namespace the
 * plugin already owns. Prefix, suffix and middle all count, and the anchor
 * still counts when a helper supplies it.
 */

function acme_option_key($id)
{
    return 'acme_entry_' . $id;
}

function acme_save_anchored()
{
    update_option('acme_' . $_POST['k'], '1');
    update_option($_POST['k'] . '_acme', '1');
    update_option('acme' . $_POST['k'] . 'suffix', '1');
    update_option(acme_option_key($_POST['k']), '1');
}

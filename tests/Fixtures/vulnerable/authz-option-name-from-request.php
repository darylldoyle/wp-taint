<?php

/**
 * The option NAME comes from the request, so the caller chooses which option to
 * write rather than what to write into it. `default_role` is an option and
 * `administrator` is a legal value for it.
 */

function acme_save_all()
{
    foreach ($_POST['option'] as $name => $value) {
        update_option($name, $value); // wp-taint-expect wp.authz.arbitrary-option-write identifier
    }
}

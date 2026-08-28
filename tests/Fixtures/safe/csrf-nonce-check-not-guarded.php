<?php

/**
 * check_admin_referer() dies on a missing nonce as readily as on a wrong one,
 * so there is nothing for an attacker to omit.
 */

function acme_save_settings_safe()
{
    check_admin_referer('acme_settings');

    update_option('acme_enabled', '1');
}

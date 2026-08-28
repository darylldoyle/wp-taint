<?php

/**
 * The documented fix, and what Better Search Replace shipped for CVE-2023-6933:
 * with classes forbidden, unserialize() returns arrays and scalars and no POP
 * chain can run.
 */

function acme_load_state_safe()
{
    return unserialize(get_option('acme_state'), array('allowed_classes' => false));
}

<?php

/**
 * Object injection through stored data. An attacker who can write this option
 * — often a subscriber, through some other plugin's meta handling — escalates
 * to code execution through a POP chain, which is more than the write gave
 * them. Three CVEs in tests/Fixtures/cve-lock.json are exactly this shape.
 */

function acme_load_state()
{
    return unserialize(get_option('acme_state')); // wp-taint-expect wp.rce.unserialize-stored unserialize_stored
}

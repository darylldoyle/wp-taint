<?php

/**
 * PHP object injection through unserialize on request data.
 */

$payload = $_COOKIE['acme_state'];

$state = unserialize($payload); // wp-taint-expect wp.rce.unserialize unserialize

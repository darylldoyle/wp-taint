<?php

/**
 * maybe_unserialize() calls unserialize() when the string looks serialised, so
 * it carries the same object injection risk.
 */

$state = maybe_unserialize($_POST['state']); // wp-taint-expect wp.rce.unserialize unserialize

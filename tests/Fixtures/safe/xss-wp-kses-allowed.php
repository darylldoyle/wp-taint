<?php

/**
 * wp_kses() with an explicit allowlist.
 */

$allowed = ['strong' => [], 'em' => []];

echo wp_kses($_POST['excerpt'], $allowed);

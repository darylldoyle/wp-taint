<?php

/**
 * unserialize() on a locally produced string.
 */

$packed = serialize(['a' => 1]);

$state = unserialize($packed);

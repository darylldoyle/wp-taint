<?php

/**
 * escapeshellarg() clears shell taint.
 */

$file = escapeshellarg($_GET['file']);

$output = shell_exec('convert ' . $file . ' out.png');

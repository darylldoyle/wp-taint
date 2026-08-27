<?php

/**
 * Command injection through shell_exec.
 */

$file = $_GET['file'];

$output = shell_exec('convert ' . $file . ' out.png'); // wp-taint-expect wp.rce.shell shell

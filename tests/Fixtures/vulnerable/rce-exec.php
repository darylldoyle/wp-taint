<?php

/**
 * Command injection through exec.
 */

$host = $_GET['host'];

exec("ping -c 1 {$host}", $out); // wp-taint-expect wp.rce.shell shell

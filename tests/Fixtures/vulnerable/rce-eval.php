<?php

/**
 * Remote code execution through eval.
 */

$expression = $_POST['expression'];

eval('return ' . $expression . ';'); // wp-taint-expect wp.rce.eval eval

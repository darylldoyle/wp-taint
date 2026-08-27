<?php

/**
 * Command injection through system.
 */

system('ls -la ' . $_POST['directory']); // wp-taint-expect wp.rce.shell shell

<?php

/**
 * escapeshellcmd() likewise.
 */

exec(escapeshellcmd('ping -c 1 ' . $_GET['host']), $out);

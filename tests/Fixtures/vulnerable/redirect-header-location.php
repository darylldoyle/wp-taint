<?php

/**
 * Open redirect through a raw Location header.
 */

header('Location: ' . $_GET['next']); // wp-taint-expect wp.header.injection header
exit;

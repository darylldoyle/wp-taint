<?php

/**
 * Arbitrary file delete.
 */

$name = $_REQUEST['attachment'];

unlink(ACME_UPLOAD_DIR . '/' . $name); // wp-taint-expect wp.path.file-write path

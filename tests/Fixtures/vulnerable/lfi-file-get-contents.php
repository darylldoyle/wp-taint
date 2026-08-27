<?php

/**
 * Arbitrary file read.
 */

$path = $_GET['file'];

echo file_get_contents(ACME_UPLOAD_DIR . '/' . $path); // wp-taint-expect wp.path.file-read path

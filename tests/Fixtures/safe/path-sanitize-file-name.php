<?php

/**
 * sanitize_file_name() strips path separators and traversal sequences, so it
 * clears path taint.
 */

$name = sanitize_file_name($_POST['attachment']);

$contents = file_get_contents(ACME_UPLOAD_DIR . '/' . $name);

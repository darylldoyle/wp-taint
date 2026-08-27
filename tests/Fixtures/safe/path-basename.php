<?php

/**
 * basename() removes any directory component, which is enough to clear path
 * traversal taint.
 */

$file = basename($_GET['file']);

echo esc_html(file_get_contents(ACME_UPLOAD_DIR . '/' . $file));

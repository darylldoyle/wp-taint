<?php

/**
 * Arbitrary file write.
 */

file_put_contents($_POST['destination'], 'ok'); // wp-taint-expect wp.path.file-write path

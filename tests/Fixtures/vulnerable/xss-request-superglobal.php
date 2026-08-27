<?php

/**
 * $_REQUEST is a source in exactly the same way $_GET and $_POST are.
 */

echo '<p>' . $_REQUEST['page_title'] . '</p>'; // wp-taint-expect wp.xss.unescaped-output html

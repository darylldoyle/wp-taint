<?php

/**
 * stripslashes() is a string operation, not an escaper.
 */

echo stripslashes($_POST['bio']); // wp-taint-expect wp.xss.unescaped-output html

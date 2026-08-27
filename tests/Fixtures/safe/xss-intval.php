<?php

/**
 * intval() clears every taint kind for the same reason.
 */

echo '<li>' . intval($_POST['quantity']) . '</li>';

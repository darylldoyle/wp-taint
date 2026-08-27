<?php

/**
 * An explicit (int) cast is equivalent to intval() for taint purposes.
 */

$page = (int) $_GET['paged'];

echo "<p>Page {$page}</p>";

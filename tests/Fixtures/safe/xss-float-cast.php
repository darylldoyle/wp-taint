<?php

/**
 * A (float) cast likewise cannot carry a payload.
 */

$price = (float) $_POST['price'];

echo '<span class="price">' . $price . '</span>';

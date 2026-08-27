<?php

/**
 * absint() casts to a non-negative integer, which clears every taint kind.
 */

$post_id = absint($_GET['post_id']);

echo '<span data-post="' . $post_id . '">' . $post_id . '</span>';

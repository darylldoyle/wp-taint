<?php

/**
 * sanitize_text_field() strips tags, so it clears html taint.
 */

$note = sanitize_text_field($_POST['note']);

echo '<p>' . $note . '</p>';

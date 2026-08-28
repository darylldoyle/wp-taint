<?php

// @wp-taint-source O07
$notes = get_option( 'fixture_o07_notes', '' );
// @wp-taint-sink O07 expect=output.unescaped
echo '<textarea name="notes">' . $notes . '</textarea>';

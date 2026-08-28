<?php

// @wp-taint-source O07
$notes = get_option( 'fixture_o07_notes', '' );
// @wp-taint-sink O07 expect=clean
echo '<textarea name="notes">' . esc_textarea( $notes ) . '</textarea>';

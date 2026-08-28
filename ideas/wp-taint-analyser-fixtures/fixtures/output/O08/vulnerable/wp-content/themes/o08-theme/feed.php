<?php

// @wp-taint-source O08
$loc = get_option( 'fixture_o08_location', '' );
// @wp-taint-sink O08 expect=output.unescaped
echo '<loc>' . $loc . '</loc>';

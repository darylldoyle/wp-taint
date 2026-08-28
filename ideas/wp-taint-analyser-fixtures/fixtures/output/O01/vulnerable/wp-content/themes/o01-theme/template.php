<?php

// @wp-taint-source O01
$title = get_option( 'fixture_o01_title', '' );
// @wp-taint-sink O01 expect=output.unescaped
echo '<h2>' . $title . '</h2>';

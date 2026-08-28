<?php

$heading = apply_filters( 'fixture_f11_heading', 'Welcome' );
// @wp-taint-sink F11 expect=flow.unsanitized_unescaped
echo '<h1>' . $heading . '</h1>';

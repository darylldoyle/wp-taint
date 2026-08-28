<?php

// @wp-taint-source O05
$html = get_option( 'fixture_o05_rich_html', '' );
// @wp-taint-sink O05 expect=output.unescaped
echo $html;

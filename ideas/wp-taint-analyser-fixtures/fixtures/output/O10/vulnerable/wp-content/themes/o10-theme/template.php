<?php

// @wp-taint-source O10
$title = get_option( 'fixture_o10_title', '' );
$title = esc_html( $title );
// @wp-taint-invalidate O10 reason=filter-after-escape
$title = apply_filters( 'fixture_o10_title', $title );
// @wp-taint-sink O10 expect=output.escape_invalidated
echo $title;

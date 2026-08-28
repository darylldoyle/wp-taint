<?php

// @wp-taint-source F15
$label = get_option( 'fixture_f15_label', 'Default' );
$label = apply_filters( 'fixture_f15_label', $label );
// @wp-taint-sink F15 expect=clean
echo '<span>' . esc_html( $label ) . '</span>';

<?php

// @wp-taint-source F15
$label = esc_html( get_option( 'fixture_f15_label', 'Default' ) );
// @wp-taint-invalidate F15 reason=filter-after-escape
$label = apply_filters( 'fixture_f15_label', $label );
// @wp-taint-sink F15 expect=output.escape_invalidated
echo '<span>' . $label . '</span>';

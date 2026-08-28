<?php

add_filter( 'fixture_f15_label', function ( $label ) {
    // replacement ignores the already-escaped incoming value
    return get_option( 'fixture_f15_override', $label );
} );

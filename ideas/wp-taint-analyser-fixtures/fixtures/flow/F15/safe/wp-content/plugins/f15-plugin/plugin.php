<?php

add_filter( 'fixture_f15_label', function ( $label ) {
    return get_option( 'fixture_f15_override', $label );
} );

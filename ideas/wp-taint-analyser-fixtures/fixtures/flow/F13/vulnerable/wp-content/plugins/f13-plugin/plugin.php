<?php

function fixture_f13_save() {
    if ( ! isset( $_POST['tagline'] ) ) { return; }
    // @wp-taint-source F13
    $tagline = wp_unslash( $_POST['tagline'] );
    // @wp-taint-sink F13 expect=input.unsanitized_storage
    update_option( 'fixture_f13_tagline', $tagline );
}

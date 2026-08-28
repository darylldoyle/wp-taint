<?php

function fixture_i01_save() {
    if ( ! isset( $_POST['display_name'] ) ) { return; }
    // @wp-taint-source I01
    $value = wp_unslash( $_POST['display_name'] );
    // @wp-taint-sink I01 expect=input.unsanitized_storage
    update_option( 'fixture_i01_display_name', $value );
}

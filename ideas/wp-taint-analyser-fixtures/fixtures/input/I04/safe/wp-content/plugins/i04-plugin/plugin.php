<?php

function fixture_i04_save_filename() {
    if ( empty( $_FILES['fixture_upload']['name'] ) ) { return; }
    // @wp-taint-source I04
    $name = sanitize_file_name( wp_unslash( $_FILES['fixture_upload']['name'] ) );
    // @wp-taint-sink I04 expect=clean
    update_post_meta( 42, 'fixture_i04_filename', $name );
}

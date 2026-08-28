<?php

function fixture_f12_save() {
    if ( isset( $_POST['subtitle'] ) ) {
        // @wp-taint-source F12
        update_option( 'fixture_f12_subtitle', sanitize_text_field( wp_unslash( $_POST['subtitle'] ) ) );
    }
}

<?php

function fixture_f02_save() {
    if ( isset( $_POST['message'] ) ) {
        // @wp-taint-source F02
        $message = sanitize_text_field( wp_unslash( $_POST['message'] ) );
        update_option( 'fixture_f02_message', $message );
    }
}
function fixture_f02_render() {
    $message = get_option( 'fixture_f02_message', '' );
    // @wp-taint-sink F02 expect=clean
    echo '<div class="notice">' . esc_html( $message ) . '</div>';
}

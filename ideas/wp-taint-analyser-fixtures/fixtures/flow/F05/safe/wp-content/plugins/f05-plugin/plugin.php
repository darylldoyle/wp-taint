<?php

function fixture_f05_ajax_save() {
    check_ajax_referer( 'fixture_f05', 'nonce' );
    // @wp-taint-source F05
    $message = isset( $_POST['message'] ) ? sanitize_text_field( wp_unslash( $_POST['message'] ) ) : '';
    update_option( 'fixture_f05_message', $message );
    wp_send_json_success();
}
function fixture_f05_admin_notice() {
    $message = get_option( 'fixture_f05_message', '' );
    // @wp-taint-sink F05 expect=clean
    echo '<div class="notice"><p>' . esc_html( $message ) . '</p></div>';
}

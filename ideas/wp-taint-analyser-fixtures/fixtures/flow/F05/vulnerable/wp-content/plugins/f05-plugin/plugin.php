<?php

function fixture_f05_ajax_save() {
    check_ajax_referer( 'fixture_f05', 'nonce' );
    // @wp-taint-source F05
    $message = isset( $_POST['message'] ) ? wp_unslash( $_POST['message'] ) : '';
    update_option( 'fixture_f05_message', $message );
    wp_send_json_success();
}
function fixture_f05_admin_notice() {
    $message = get_option( 'fixture_f05_message', '' );
    // @wp-taint-sink F05 expect=flow.unsanitized_unescaped
    echo '<div class="notice"><p>' . $message . '</p></div>';
}

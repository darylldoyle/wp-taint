<?php

function fixture_f08_save() {
    // @wp-taint-source F08
    $incoming = isset( $_POST['profile'] ) ? wp_unslash( $_POST['profile'] ) : array();
    $profile = array_merge( array( 'role' => 'reader' ), $incoming );
    update_option( 'fixture_f08_profile', $profile );
}
function fixture_f08_render() {
    $profile = get_option( 'fixture_f08_profile', array() );
    $name = isset( $profile['name'] ) ? $profile['name'] : '';
    // @wp-taint-sink F08 expect=flow.unsanitized_unescaped
    echo '<strong>' . $name . '</strong>';
}

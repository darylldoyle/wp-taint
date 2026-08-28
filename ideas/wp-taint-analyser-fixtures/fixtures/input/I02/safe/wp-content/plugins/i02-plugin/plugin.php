<?php

function fixture_i02_save() {
    // @wp-taint-source I02
    $settings = isset( $_POST['fixture_settings'] ) ? wp_unslash( $_POST['fixture_settings'] ) : array();
    $settings = map_deep( $settings, 'sanitize_text_field' );
    $settings['version'] = '1';
    // @wp-taint-sink I02 expect=clean
    update_option( 'fixture_i02_settings', $settings );
}

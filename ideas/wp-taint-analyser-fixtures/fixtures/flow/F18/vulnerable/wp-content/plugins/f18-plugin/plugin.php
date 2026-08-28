<?php

function fixture_f18_script() {
    // @wp-taint-source F18
    $message = isset( $_GET['message'] ) ? wp_unslash( $_GET['message'] ) : '';
    $script = "window.fixtureMessage = '" . $message . "';";
    // @wp-taint-sink F18 expect=flow.unsanitized_unescaped
    wp_add_inline_script( 'fixture-app', $script, 'before' );
}

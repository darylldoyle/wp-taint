<?php

function fixture_f09_render() {
    $name = 'Anonymous';
    if ( isset( $_GET['name'] ) ) {
        // @wp-taint-source F09
        $name = wp_unslash( $_GET['name'] );
    }
    // @wp-taint-sink F09 expect=flow.unsanitized_unescaped
    echo '<p>Hello ' . $name . '</p>';
}

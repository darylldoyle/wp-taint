<?php

function fixture_f04_notice_link() {
    // @wp-taint-source F04
    $base = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
    $url = add_query_arg( array( 'dismiss' => '1' ), $base );
    // @wp-taint-sink F04 expect=flow.unsanitized_unescaped
    echo '<a href="' . $url . '">Dismiss</a>';
}

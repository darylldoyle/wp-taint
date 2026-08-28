<?php

function fixture_f01_render() {
    // @wp-taint-source F01
    $query = isset( $_GET['q'] ) ? wp_unslash( $_GET['q'] ) : '';
    $label = trim( $query );
    // @wp-taint-sink F01 expect=flow.unsanitized_unescaped
    echo '<p>' . $label . '</p>';
}

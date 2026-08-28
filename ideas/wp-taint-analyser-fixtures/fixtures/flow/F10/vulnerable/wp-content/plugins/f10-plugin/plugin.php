<?php

function fixture_f10_render() {
    // @wp-taint-source F10
    $label = isset( $_GET['label'] ) ? wp_unslash( $_GET['label'] ) : '';
    $html = sprintf( '<span class="tag">%s</span>', $label );
    // @wp-taint-sink F10 expect=flow.unsanitized_unescaped
    echo $html;
}

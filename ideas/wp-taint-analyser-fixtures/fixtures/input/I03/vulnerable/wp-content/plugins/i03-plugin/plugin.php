<?php

function fixture_i03_save() {
    if ( ! isset( $_GET['page_id'] ) ) { return; }
    // @wp-taint-source I03
    $page_id = wp_unslash( $_GET['page_id'] );
    // @wp-taint-sink I03 expect=input.unsanitized_storage
    update_post_meta( 42, 'fixture_i03_page_id', $page_id );
}

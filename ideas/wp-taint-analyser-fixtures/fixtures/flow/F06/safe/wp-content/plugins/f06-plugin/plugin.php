<?php

function fixture_f06_rest_save( WP_REST_Request $request ) {
    // @wp-taint-source F06
    $caption = sanitize_text_field( $request->get_param( 'caption' ) );
    update_post_meta( 42, 'fixture_f06_caption', $caption );
    return rest_ensure_response( array( 'saved' => true ) );
}
function fixture_f06_render_block( $attributes, $content, $block ) {
    $caption = get_post_meta( $block->context['postId'], 'fixture_f06_caption', true );
    // @wp-taint-sink F06 expect=clean
    return '<figcaption>' . esc_html( $caption ) . '</figcaption>';
}

<?php

function fixture_i05_rest_save( WP_REST_Request $request ) {
    // @wp-taint-source I05
    $bio = $request->get_param( 'bio' );
    // @wp-taint-sink I05 expect=input.unsanitized_storage
    update_user_meta( get_current_user_id(), 'fixture_i05_bio', $bio );
    return new WP_REST_Response( array( 'ok' => true ) );
}

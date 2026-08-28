<?php

function fixture_f14_banner() {
    $banner = esc_html( get_option( 'fixture_f14_banner', 'Hello' ) );
    // @wp-taint-invalidate F14 reason=filter-after-escape
    return apply_filters( 'fixture_f14_banner', $banner );
}

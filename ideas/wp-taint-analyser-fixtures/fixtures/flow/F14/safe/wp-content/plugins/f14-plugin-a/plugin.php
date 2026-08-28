<?php

function fixture_f14_banner() {
    return apply_filters( 'fixture_f14_banner', get_option( 'fixture_f14_banner', 'Hello' ) );
}

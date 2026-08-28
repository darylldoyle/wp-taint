<?php

$tagline = get_option( 'fixture_f13_tagline', '' );
echo '<p>' . esc_html( $tagline ) . '</p>';

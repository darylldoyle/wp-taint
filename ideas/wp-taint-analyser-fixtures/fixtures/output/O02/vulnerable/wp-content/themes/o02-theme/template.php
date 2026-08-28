<?php

// @wp-taint-source O02
$class = get_post_meta( get_the_ID(), 'fixture_o02_class', true );
// @wp-taint-sink O02 expect=output.unescaped
echo '<div class="' . $class . '">Fixture</div>';

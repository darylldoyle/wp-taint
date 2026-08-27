<?php

/**
 * wp_kses_post() is the right choice when limited markup is intended.
 */

echo wp_kses_post($_POST['bio']);

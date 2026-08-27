<?php

/**
 * sanitize_text_field() strips the CR and LF that make header injection
 * possible.
 */

header('X-Acme-View: ' . sanitize_text_field($_GET['view']));

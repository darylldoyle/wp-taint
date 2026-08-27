<?php

/**
 * Header injection via setcookie value.
 */

setcookie('acme_pref', $_GET['pref']); // wp-taint-expect wp.header.injection header

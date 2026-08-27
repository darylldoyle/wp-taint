<?php

/**
 * An integer value cannot inject a header.
 */

setcookie('acme_page', (string) absint($_GET['paged']));

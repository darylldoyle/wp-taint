<?php

/**
 * Writing request data into an option is the write side of second-order taint.
 * It is reported only under --stored-taint-writes, which is off by default.
 */

update_option('acme_last_search', sanitize_text_field(wp_unslash($_GET['s'])));

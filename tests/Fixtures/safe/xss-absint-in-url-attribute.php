<?php

/**
 * absint() reduces its argument to an integer, which cannot carry a breakout in
 * any context — including a URL attribute, where esc_url() would otherwise be
 * the required escaper. The wrong-context rule must not report it.
 */

printf('<a href="?id=%s">edit</a>', absint($_GET['id']));

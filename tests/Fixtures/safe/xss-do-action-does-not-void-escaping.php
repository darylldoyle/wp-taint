<?php

/**
 * do_action() dispatches to its callbacks and hands nothing back: an action's
 * callbacks receive the arguments and their return values are discarded. So an
 * escaped value does not lose its escaping by being passed through one, and the
 * engine must not raise escape-voided here the way it does for apply_filters(),
 * which returns what its callbacks produced.
 *
 * The return is assigned and echoed to make the point at the sharpest angle: even
 * when a caller mistakes an action for a filter, nothing filtered comes back.
 */

function acme_render_notice_safe()
{
    $notice = do_action('acme_before_notice', esc_html($_GET['msg']));
    echo $notice;
}

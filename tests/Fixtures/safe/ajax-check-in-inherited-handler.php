<?php

/**
 * An AJAX callback inherited from a base class that does check a capability.
 *
 * The registration spells the callback `array( $this, 'handle' )` on the
 * subclass, but `handle()` lives on the parent. The AST spells its key under
 * the subclass's name; canonicalization resolves it to the defining class so
 * the call graph can walk the body and see the check, instead of reporting
 * "could not walk" and falling back to a heuristic.
 */

class Acme_Ajax_Base
{
    public function handle()
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(null, 403);
        }

        update_option('acme_flag', sanitize_text_field(wp_unslash($_POST['flag'])));

        wp_send_json_success();
    }
}

class Acme_Ajax_Controller extends Acme_Ajax_Base
{
    public function register()
    {
        add_action('wp_ajax_acme_flag', [$this, 'handle']);
    }
}

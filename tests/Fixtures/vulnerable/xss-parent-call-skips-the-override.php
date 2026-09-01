<?php

/**
 * `parent::` dispatches to the parent's body, not the override.
 *
 * The child's own `val()` returns a literal; the parent's returns request
 * data. Resolving `parent::val()` to the override would call the safe body
 * and lose the flow — PHP calls the parent's, and so does the resolver.
 */

class Acme_Value_Base
{
    public function val()
    {
        return $_GET['x'];
    }
}

class Acme_Value extends Acme_Value_Base
{
    public function val()
    {
        return 'safe';
    }

    public function show()
    {
        echo parent::val(); // wp-taint-expect wp.xss.unescaped-output html
    }
}

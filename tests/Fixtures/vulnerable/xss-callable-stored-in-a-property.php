<?php

/**
 * A callable stashed on a property in the constructor, called elsewhere.
 *
 * `call_user_func( $this->handler, … )` is a property fetch no single body can
 * see through; the cross-method index of property-assigned callables resolves
 * it when every readable write to the property agrees. The safe counterpart
 * proves the resolved body's own escaping is credited.
 */

function acme_print_raw($v)
{
    echo $v; // wp-taint-expect wp.xss.unescaped-output html
}

class Acme_Runner
{
    private $handler;

    public function __construct()
    {
        $this->handler = 'acme_print_raw';
    }

    public function run()
    {
        call_user_func($this->handler, $_GET['a']);
    }
}

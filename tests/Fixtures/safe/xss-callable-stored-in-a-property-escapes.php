<?php

/**
 * The safe counterpart: the property-held callable escapes its argument.
 *
 * `array( $this, 'render' )` on a property resolves through the same index,
 * and the resolved body's esc_html() is credited. A property whose writes
 * disagree — or hold anything the index cannot read — stays unresolved and is
 * handled by --dynamic-calls, never guessed.
 */

class Acme_Safe_Runner
{
    private $pair;

    public function __construct()
    {
        $this->pair = [$this, 'render'];
    }

    public function render($v)
    {
        echo esc_html($v);
    }

    public function run()
    {
        call_user_func($this->pair, $_GET['b']);
    }
}

<?php

/**
 * Taint flowing through a method the subclass inherits.
 *
 * Resolving inherited calls must not only clear the safe helpers — it has to
 * carry the dangerous ones too. `raw()` lives on the parent and returns
 * request data; the call is made on the child.
 */

class Acme_Input_Base
{
    public function raw()
    {
        return $_GET['q'];
    }
}

class Acme_Input extends Acme_Input_Base
{
}

function acme_show()
{
    $input = new Acme_Input();

    echo $input->raw(); // wp-taint-expect wp.xss.unescaped-output html
}

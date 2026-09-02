<?php

/**
 * Taint stored in a property by the base class, read through the subclass.
 *
 * A write lands under the class whose method performed it — here the parent's
 * constructor — but the property is one storage slot on the instance, so the
 * subclass's read must see it. Under flat per-class keys this flow was
 * invisible.
 */

class Acme_Holder_Base
{
    protected $value;

    public function __construct()
    {
        $this->value = $_GET['x'];
    }
}

class Acme_Holder extends Acme_Holder_Base
{
    public function show()
    {
        echo $this->value; // wp-taint-expect wp.xss.unescaped-output html
    }
}

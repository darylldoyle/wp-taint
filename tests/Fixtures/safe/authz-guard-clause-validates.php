<?php

/**
 * A guard clause constrains the value on every path that reaches the write.
 * php-cfg gives the two branches their own operands for is_*(), and dominance
 * answers it for the checks it does not assert on.
 */

function acme_render_id()
{
    $id = $_GET['id'];

    if (! ctype_digit($id)) {
        return;
    }

    echo $id;
}

function acme_render_mode()
{
    $mode = $_GET['mode'];

    if (! in_array($mode, array('grid', 'list', 'table'), true)) {
        return;
    }

    echo $mode;
}

function acme_save_int()
{
    $id = $_GET['id'];

    if (! is_int($id)) {
        return;
    }

    echo $id;
}

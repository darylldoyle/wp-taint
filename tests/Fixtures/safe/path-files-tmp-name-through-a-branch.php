<?php

/**
 * `tmp_name` read from a value merged from two `$_FILES` entries.
 *
 * Both branches are `$_FILES` fetches and `tmp_name` is PHP's own path in
 * either, so the merge is as safe as each side. The phi is followed only when
 * every input qualifies — see the vulnerable counterpart, where one branch is
 * `$_POST` and the read stays tainted.
 */

function acme_import()
{
    $file = empty($_FILES['csv']) ? $_FILES['fallback'] : $_FILES['csv'];

    return fopen($file['tmp_name'], 'r');
}

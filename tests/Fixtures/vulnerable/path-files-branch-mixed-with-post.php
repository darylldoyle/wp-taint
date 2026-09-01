<?php

/**
 * A merge where only one branch is a `$_FILES` entry.
 *
 * The other branch is `$_POST`, whose every key is the attacker's, so the
 * `tmp_name` read cannot be cleared: the value could be the `$_POST` branch's.
 * One qualifying branch must never launder the other.
 */

function acme_import_mixed()
{
    $file = empty($_FILES['csv']) ? $_POST['path'] : $_FILES['csv'];

    return fopen($file['tmp_name'], 'r'); // wp-taint-expect wp.path.file-read path
}

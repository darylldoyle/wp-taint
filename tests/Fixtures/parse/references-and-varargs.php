<?php

function accumulate(array &$carry, string ...$values): void
{
    foreach ($values as $value) {
        $carry[] = $value;
    }
}

function &getRef(array &$store): mixed
{
    return $store['key'];
}

$store = ['key' => 'initial'];
$out = [];

accumulate($out, 'a', 'b', 'c');
accumulate($out, ...['d', 'e']);
accumulate($out, ...['values' => 'named']);

$ref = &getRef($store);
$ref = 'changed';

foreach ($out as &$item) {
    $item = strtoupper($item);
}
unset($item);

echo implode(',', $out), $store['key'];

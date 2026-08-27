<?php
$a = 1;
$b = 2;

$x = $a > $b ? 'a' : ($a < $b ? 'b' : 'equal');
$y = $a ?: $b;
$z = $a ?? $b;
$w = ($a ?? null) ?: ($b ?? 'fallback');

$deep = $a > 0
    ? ($b > 0 ? 'both' : 'first')
    : ($b > 0 ? 'second' : 'neither');

echo $x, $y, $z, $w, $deep;

<?php
$pairs = [[1, 2], [3, 4]];

list($a, $b) = [1, 2];
[$c, $d] = [3, 4];
['x' => $e, 'y' => $f] = ['x' => 5, 'y' => 6];
[, $g] = [7, 8];
[[$h, $i], [$j, $k]] = $pairs;

foreach ($pairs as [$m, $n]) {
    echo $m + $n;
}

echo $a + $b + $c + $d + $e + $f + $g + $h + $i + $j + $k;

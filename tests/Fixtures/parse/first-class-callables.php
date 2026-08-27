<?php

final class Maths
{
    public static function double(int $n): int
    {
        return $n * 2;
    }

    public function triple(int $n): int
    {
        return $n * 3;
    }
}

$strlen = strlen(...);
$double = Maths::double(...);
$maths = new Maths();
$triple = $maths->triple(...);

echo $strlen('abc'), $double(2), $triple(3);

$nullsafe = $maths?->triple(1);
echo $nullsafe ?? 0;

echo array_map(static fn (int $n): int => $n + 1, [1, 2, 3])[0];

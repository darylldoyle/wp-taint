<?php

function risky(int $n): int
{
    try {
        if ($n < 0) {
            throw new InvalidArgumentException('negative');
        }

        return intdiv(10, $n);
    } catch (DivisionByZeroError | ArithmeticError $e) {
        return 0;
    } catch (InvalidArgumentException) {
        return -1;
    } finally {
        error_log('done');
    }
}

$result = risky(2);

$closure = static function () use ($result): int {
    static $calls = 0;
    $calls++;

    return $result + $calls;
};

echo $closure(), $closure();

echo throw_helper();

function throw_helper(): string
{
    return true ? 'ok' : throw new RuntimeException('never');
}

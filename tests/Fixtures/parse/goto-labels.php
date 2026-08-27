<?php
$i = 0;

start:
$i++;

if ($i < 3) {
    goto start;
}

if ($i === 3) {
    goto done;
}

echo 'unreachable';

done:
echo $i;

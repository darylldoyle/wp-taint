<?php
$name = 'value';
$value = 'indirect';
echo $$name;
echo ${$name};
echo ${'val' . 'ue'};

class Holder
{
    public string $prop = 'p';
}

$h = new Holder();
$k = 'prop';
echo $h->$k;
echo $h->{'pr' . 'op'};

$fn = 'strlen';
echo $fn('x');

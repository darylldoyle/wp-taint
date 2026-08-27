<?php
$name = 'world';
$a = <<<HTML
    <p>Hello {$name}</p>
    <p>Escaped \$name stays literal</p>
    HTML;

$b = <<<'RAW'
    No $interpolation here at all.
    RAW;

$c = <<<"DOUBLE"
Complex: {$_SERVER['HTTP_HOST']} and ${name}
DOUBLE;

echo $a, $b, $c;

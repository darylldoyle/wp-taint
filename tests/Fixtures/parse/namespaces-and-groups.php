<?php

declare(strict_types=1);

namespace Acme\Plugin\Admin;

use Acme\Plugin\{Contracts\Renderable, Support\Str};
use Acme\Plugin\Support\Arr as ArrayHelper;
use function Acme\Plugin\Support\slugify;
use const Acme\Plugin\VERSION;

const LOCAL = 'local';

function helper(): string
{
    return slugify(VERSION . LOCAL);
}

final class Screen
{
    public function render(): string
    {
        return ArrayHelper::first([Str::class, Renderable::class]) . helper();
    }
}

<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

enum MatcherKind: string
{
    case Superglobal = 'superglobal';
    case Func = 'function';
    case Method = 'method';
    case StaticMethod = 'static_method';
    case Construct = 'construct';
}

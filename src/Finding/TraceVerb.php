<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Finding;

/**
 * A closed set. Trace steps never carry free-form verbs, because the verb is
 * what a reader scans for when triaging.
 */
enum TraceVerb: string
{
    case Source = 'source';
    case Propagate = 'propagate';
    case Sanitize = 'sanitize';
    case Call = 'call';
    case Return_ = 'return';
    case Sink = 'sink';
}

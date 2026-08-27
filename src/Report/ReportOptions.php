<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Report;

final class ReportOptions
{
    public function __construct(
        public readonly bool $verbose = false,
        public readonly bool $colour = true,
        public readonly bool $traceFull = false,
        public readonly string $toolVersion = '0.1.0',
        public readonly int $collapseTracesLongerThan = 12,
    ) {
    }
}

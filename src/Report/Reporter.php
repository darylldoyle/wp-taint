<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Report;

use Enshrined\WpTaint\Scan\ScanResult;

interface Reporter
{
    public function render(ScanResult $result, ReportOptions $options): string;
}

<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * Something the engine could not do properly.
 *
 * Warnings are surfaced, never swallowed. An iteration cap that trips silently
 * is a false negative nobody knows about.
 */
final class AnalysisWarning
{
    public function __construct(
        public readonly string $file,
        public readonly string $functionName,
        public readonly string $message,
    ) {
    }
}

<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

use Enshrined\WpTaint\Finding\RuleDefinition;

final class RuleMetadata
{
    public function __construct(
        public readonly string $id,
        public readonly string $title,
        public readonly string $description,
        public readonly string $remediation,
        public readonly ?string $cwe = null,
        public readonly ?string $message = null,
    ) {
    }

    public function toDefinition(): RuleDefinition
    {
        return new RuleDefinition($this->id, $this->title, $this->description, $this->remediation, $this->cwe);
    }

    public function message(): string
    {
        return $this->message ?? $this->title;
    }
}

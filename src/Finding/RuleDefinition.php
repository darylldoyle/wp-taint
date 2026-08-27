<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Finding;

/**
 * Rule metadata carried inline on every finding.
 *
 * JSON output has to be self-describing: an agent or a reviewer reading
 * findings.json cold should not need a lookup table to understand a result.
 */
final class RuleDefinition
{
    public function __construct(
        public readonly string $id,
        public readonly string $title,
        public readonly string $description,
        public readonly string $remediation,
        public readonly ?string $cwe = null,
    ) {
    }

    /**
     * @return array{title: string, description: string, remediation: string, cwe?: string}
     */
    public function toArray(): array
    {
        $data = [
            'title' => $this->title,
            'description' => $this->description,
            'remediation' => $this->remediation,
        ];

        if ($this->cwe !== null) {
            $data['cwe'] = $this->cwe;
        }

        return $data;
    }
}

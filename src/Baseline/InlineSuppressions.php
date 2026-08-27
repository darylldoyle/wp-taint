<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Baseline;

use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\FindingCollection;

/**
 * `// wp-taint-ignore-next-line <rule-id> -- <reason>`
 *
 * The reason is mandatory. A suppression without one is reported as an error of
 * its own, because "someone silenced this and nobody knows why" is a worse
 * state than the original finding.
 */
final class InlineSuppressions
{
    private const PATTERN = '/(?:\/\/|#|\/\*)\s*wp-taint-ignore-next-line\s+(?<rule>[a-zA-Z0-9._*-]+)(?<rest>.*)$/';

    /** @var array<string, list<string>> `file:line` => suppressed rule ids */
    private array $suppressions = [];

    /** @var list<MalformedSuppression> */
    private array $malformed = [];

    public function addFile(string $relativePath, string $source): void
    {
        $lines = preg_split('/\r\n|\r|\n/', $source);

        if ($lines === false) {
            return;
        }

        foreach ($lines as $index => $line) {
            if (preg_match(self::PATTERN, $line, $matches) !== 1) {
                continue;
            }

            $lineNumber = $index + 1;
            $rest = rtrim(rtrim(trim($matches['rest']), '*/'));

            if (! str_starts_with($rest, '--') || trim(substr($rest, 2)) === '') {
                $this->malformed[] = new MalformedSuppression(
                    $relativePath,
                    $lineNumber,
                    $matches['rule'],
                    'no reason given; the form is "-- <reason>"',
                );

                continue;
            }

            $this->suppressions[$relativePath . ':' . ($lineNumber + 1)][] = $matches['rule'];
        }
    }

    public function suppresses(Finding $finding): bool
    {
        $rules = $this->suppressions[$finding->file . ':' . $finding->line] ?? [];

        foreach ($rules as $rule) {
            if ($rule === '*' || $rule === $finding->ruleId) {
                return true;
            }

            // `wp.xss.*` suppresses every rule in that family.
            if (str_ends_with($rule, '*') && str_starts_with($finding->ruleId, rtrim($rule, '*'))) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array{kept: FindingCollection, suppressed: int}
     */
    public function apply(FindingCollection $findings): array
    {
        $suppressed = 0;

        $kept = $findings->filter(function (Finding $finding) use (&$suppressed): bool {
            if (! $this->suppresses($finding)) {
                return true;
            }

            $suppressed++;

            return false;
        });

        return ['kept' => $kept, 'suppressed' => $suppressed];
    }

    /**
     * @return list<MalformedSuppression>
     */
    public function malformed(): array
    {
        return $this->malformed;
    }
}

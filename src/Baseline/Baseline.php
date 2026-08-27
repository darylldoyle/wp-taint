<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Baseline;

use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\FindingCollection;
use JsonException;
use RuntimeException;

/**
 * A set of accepted findings, matched by fingerprint.
 *
 * Fingerprints deliberately exclude the line number, so a baseline survives
 * unrelated edits above a finding. A baseline that invalidates on every commit
 * is a baseline nobody keeps.
 */
final class Baseline
{
    public const SCHEMA_VERSION = '1.0';

    /**
     * @param array<string, string> $fingerprints fingerprint => the rule it was recorded for
     */
    private function __construct(private readonly array $fingerprints)
    {
    }

    public static function empty(): self
    {
        return new self([]);
    }

    public static function fromFile(string $path): self
    {
        $contents = file_get_contents($path);

        if ($contents === false) {
            throw new RuntimeException(sprintf('Unable to read baseline file: %s', $path));
        }

        try {
            $data = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $error) {
            throw new RuntimeException(sprintf('Baseline file %s is not valid JSON: %s', $path, $error->getMessage()));
        }

        if (! is_array($data) || ! isset($data['findings']) || ! is_array($data['findings'])) {
            throw new RuntimeException(sprintf('Baseline file %s has no "findings" array.', $path));
        }

        $fingerprints = [];

        foreach ($data['findings'] as $entry) {
            if (! is_array($entry) || ! isset($entry['fingerprint']) || ! is_string($entry['fingerprint'])) {
                continue;
            }

            $ruleId = isset($entry['ruleId']) && is_string($entry['ruleId']) ? $entry['ruleId'] : '';
            $fingerprints[$entry['fingerprint']] = $ruleId;
        }

        return new self($fingerprints);
    }

    public function contains(Finding $finding): bool
    {
        return isset($this->fingerprints[$finding->fingerprint]);
    }

    public function count(): int
    {
        return count($this->fingerprints);
    }

    /**
     * @return array{kept: FindingCollection, suppressed: int}
     */
    public function apply(FindingCollection $findings): array
    {
        $suppressed = 0;

        $kept = $findings->filter(function (Finding $finding) use (&$suppressed): bool {
            if (! $this->contains($finding)) {
                return true;
            }

            $suppressed++;

            return false;
        });

        return ['kept' => $kept, 'suppressed' => $suppressed];
    }
}

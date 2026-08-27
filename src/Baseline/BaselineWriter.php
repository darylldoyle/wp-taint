<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Baseline;

use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\FindingCollection;
use RuntimeException;

/**
 * Writes a baseline file.
 *
 * The file records the rule, file and message alongside each fingerprint. None
 * of that is used for matching — the fingerprint alone is — but a baseline
 * containing nothing but opaque hashes is a baseline nobody can review, and
 * reviewing it is the point: the suppressed set is debt, and debt has to stay
 * legible.
 *
 * No line numbers and no timestamps, so the file only changes when the set of
 * accepted findings changes.
 */
final class BaselineWriter
{
    public function write(string $path, FindingCollection $findings): int
    {
        $entries = array_map(
            static fn (Finding $finding): array => [
                'fingerprint' => $finding->fingerprint,
                'ruleId' => $finding->ruleId,
                'severity' => $finding->severity->value,
                'file' => $finding->file,
                'message' => $finding->message,
            ],
            $findings->all(),
        );

        usort(
            $entries,
            static fn (array $a, array $b): int => [$a['file'], $a['ruleId'], $a['fingerprint']]
                <=> [$b['file'], $b['ruleId'], $b['fingerprint']],
        );

        $payload = [
            'schemaVersion' => Baseline::SCHEMA_VERSION,
            'tool' => 'wp-taint',
            'findings' => $entries,
        ];

        $encoded = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";

        if (file_put_contents($path, $encoded) === false) {
            throw new RuntimeException(sprintf('Unable to write baseline file: %s', $path));
        }

        return count($entries);
    }
}

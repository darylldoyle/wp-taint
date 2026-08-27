<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Finding;

/**
 * Stable identity for a finding, used for baselining and for
 * `partialFingerprints` in SARIF.
 *
 * Deliberately excludes the line number. Hashing the line would invalidate the
 * whole baseline on any unrelated edit above the finding, which makes the
 * baseline worthless within a day of adopting it.
 */
final class Fingerprint
{
    /**
     * @param string $sinkIdentity the sink construct or function name, e.g. `echo` or `wpdb::query`
     * @param string $snippet      the raw source line the sink sits on
     */
    public static function compute(
        string $ruleId,
        string $relativeFile,
        string $sinkIdentity,
        string $snippet,
    ): string {
        $material = implode("\0", [
            $ruleId,
            $relativeFile,
            $sinkIdentity,
            self::normalise($snippet),
        ]);

        return substr(hash('sha256', $material), 0, 16);
    }

    /**
     * Collapse whitespace so a reformat does not change the fingerprint.
     *
     * Quoted string contents are preserved: two different literals on
     * otherwise identical lines are genuinely different findings.
     */
    private static function normalise(string $snippet): string
    {
        $collapsed = preg_replace('/\s+/', ' ', $snippet);

        return trim($collapsed ?? $snippet);
    }
}

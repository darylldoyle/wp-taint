<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Baseline;

use Enshrined\WpTaint\Finding\Acknowledgement;
use Enshrined\WpTaint\Finding\Finding;

/**
 * Reads WordPress Coding Standards `phpcs:ignore` comments, and only the ones
 * that are a deliberate, line-specific acknowledgement.
 *
 * ```php
 * echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from esc_html'd parts
 * ```
 *
 * A named, line-specific ignore for the sniff a rule maps to is the author
 * saying "I looked at this line, and here is why". That is worth something: the
 * finding moves to a notice instead of a high, with the reason in its trace.
 *
 * Three kinds of ignore are deliberately NOT honoured, because none of them is
 * that signal:
 *
 * - **A bare `phpcs:ignore`** with no sniff named. It silences everything,
 *   including formatting, so it says nothing about security in particular.
 * - **A sniff that does not match the finding's rule.** An `EscapeOutput`
 *   ignore does not acknowledge an SQL finding.
 * - **`phpcs:disable` / `phpcs:enable` ranges.** A block disable is how bad
 *   code gets hidden from the linter wholesale, which is exactly where the
 *   analyser should keep looking. Only the per-line form counts.
 */
final class PhpcsSuppressions
{
    /**
     * A named sniff needs at least Standard.Category.Sniff, three segments, to
     * count. `WordPress.Security` is a category, too broad to be a review of
     * one line.
     */
    private const MIN_SNIFF_SEGMENTS = 3;

    // The trailing close-tag group lets a line-specific ignore sit right before
    // a PHP closing tag, as in `<?php echo $x; // phpcs:ignore Std.Cat.Sniff`
    // followed by the closing tag on the same line. PHP ends a `//` comment at
    // the closing tag, so the ignore is still line-specific; the tag is the only
    // trailing content accepted, not arbitrary text, and it is kept out of a
    // captured `-- reason`.
    private const PATTERN = '/(?:\/\/|#|\/\*)\s*phpcs:ignore\s+(?<sniffs>[A-Za-z0-9_.,\s]+?)\s*'
        . '(?:--\s*(?<reason>.*?))?\s*(?:\*\/)?\s*(?:\?>)?$/';

    /** @var array<string, array{sniffs: list<string>, reason: ?string}> `file:line` => acknowledgement */
    private array $byLine = [];

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

            $sniffs = self::sniffs($matches['sniffs']);

            if ($sniffs === []) {
                continue;
            }

            // A comment with code before it ignores that same line; a comment
            // on a line of its own ignores the next line. This is phpcs's own
            // rule, and it is what lets the ignore sit above a long statement.
            $before = trim(substr($line, 0, (int) strpos($line, 'phpcs:ignore')));
            $isTrailing = $before !== '' && ! str_starts_with($before, '//') && ! str_starts_with($before, '#')
                && ! str_starts_with($before, '/*');
            $target = $relativePath . ':' . ($index + 1 + ($isTrailing ? 0 : 1));

            $this->byLine[$target] = [
                'sniffs' => $sniffs,
                'reason' => isset($matches['reason']) && trim($matches['reason']) !== ''
                    ? trim($matches['reason'])
                    : null,
            ];
        }
    }

    /**
     * The acknowledgement for a finding, or null when the line carries no
     * matching named ignore.
     *
     * @param list<string> $ruleSniffs the sniffs the finding's rule maps to
     */
    public function acknowledgementFor(Finding $finding, array $ruleSniffs): ?Acknowledgement
    {
        if ($ruleSniffs === []) {
            return null;
        }

        $entry = $this->byLine[$finding->file . ':' . $finding->line] ?? null;

        if ($entry === null) {
            return null;
        }

        foreach ($entry['sniffs'] as $ignored) {
            foreach ($ruleSniffs as $ruleSniff) {
                // Exact, or the ignore names the sniff and the rule maps to one
                // of its error codes: `WordPress.Security.EscapeOutput` covers
                // `WordPress.Security.EscapeOutput.OutputNotEscaped`.
                if ($ruleSniff === $ignored || str_starts_with($ruleSniff, $ignored . '.')) {
                    return new Acknowledgement($ignored, $entry['reason']);
                }
            }
        }

        return null;
    }

    /**
     * The comma-separated sniff list, keeping only names specific enough to be
     * a real acknowledgement.
     *
     * @return list<string>
     */
    private static function sniffs(string $raw): array
    {
        $sniffs = [];

        foreach (explode(',', $raw) as $piece) {
            $sniff = trim($piece);

            if ($sniff !== '' && substr_count($sniff, '.') + 1 >= self::MIN_SNIFF_SEGMENTS) {
                $sniffs[] = $sniff;
            }
        }

        return $sniffs;
    }
}

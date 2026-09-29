<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * `preg_replace( '/[^a-z0-9_]/', '', $value )` — strip everything but an
 * allowlist.
 *
 * A real and effective sanitizer, and one the engine used to model as a plain
 * propagator. WP Super Cache runs a filter whose callbacks read the user agent
 * and then writes exactly this, with a comment saying why:
 *
 * ```php
 * // Filters above may return arbitrary data, so restrict it to a safe set of characters.
 * $extra_str = preg_replace( '/[^a-zA-Z0-9_-]/', '', (string) $extra_str );
 * ```
 *
 * 146 sites in the corpus use the idiom.
 *
 * ## What it can and cannot prove
 *
 * The output can only contain characters the class retained, and what that
 * proves, kind by kind, is {@see CharacterProof}'s. `[^0-9]` clears everything.
 * `[^a-zA-Z0-9 ]` clears HTML, and SQL inside quotes only: outside them the
 * space is enough for `1 OR 1`. It says nothing useful about a value used as a
 * path, because a bare word is still a filename.
 *
 * Everything here fails closed. A pattern that is not a literal, is not a single
 * negated class, uses a construct this does not understand, or carries a flag
 * that changes what the class means, clears nothing and the call stays a
 * propagator.
 */
final class AllowlistPattern
{
    /**
     * What this call proves about its result, or null when it proves nothing.
     *
     * @param string $pattern     the literal first argument
     * @param string $replacement the literal second argument
     */
    public static function clears(string $pattern, string $replacement): ?CharacterProof
    {
        // Checked first, because the CSV shape is an anchored *positive* class
        // and `retainedCharacters()` only understands a negated one — it
        // returns null here, and the allowlist path would leave before asking.
        $csv = self::neutralisesCsvFormulas($pattern, $replacement)
            ? CharacterProof::csvPrefixed()
            : null;

        $retained = self::retainedCharacters($pattern);

        if ($retained === null) {
            return $csv;
        }

        // Whatever is substituted in ends up in the output too, so it is held
        // to the same standard as the characters the class kept.
        $proof = CharacterProof::ofCharacters($retained . $replacement);
        $proof = $csv === null ? $proof : $proof->and($csv);

        return $proof->clears->isEmpty() ? null : $proof;
    }

    /**
     * The documented fix for CSV formula injection, recognised.
     *
     * A spreadsheet treats a cell beginning `=`, `+`, `-` or `@` as a formula.
     * Prefixing one with an apostrophe stops that, and it is what
     * `wp.output.csv-injection` tells people to do:
     *
     *     $name = preg_replace( '/^([=+\-@])/', "'$1", $row['name'] );
     *
     * Asking for something and then not crediting it when it is done is the
     * same defect as advice that cannot be followed. This is the one shape that
     * counts: anchored at the start, a class covering all four characters, and
     * a replacement that begins with an apostrophe.
     *
     * The apostrophe has to be first in the replacement. `$1'` puts it *after*
     * the `=`, which neutralises nothing. A tab or a space does not count:
     * `trim()` removes either, and so do readers that strip a cell's leading
     * whitespace.
     *
     * The proof covers the first character only, so the value keeps
     * `csv_prefixed`. See {@see TaintKind::CsvPrefixed}.
     */
    private static function neutralisesCsvFormulas(string $pattern, string $replacement): bool
    {
        if ($replacement === '' || $replacement[0] !== "'") {
            return false;
        }

        $body = self::patternBody($pattern);

        if ($body === null || ! str_starts_with($body, '^')) {
            return false;
        }

        $class = self::firstCharacterClass($body);

        if ($class === null) {
            return false;
        }

        foreach (['=', '+', '-', '@'] as $formula) {
            if (! str_contains($class, $formula)) {
                return false;
            }
        }

        return true;
    }

    /**
     * The contents of the first `[...]` in a pattern body, escapes flattened.
     */
    private static function firstCharacterClass(string $body): ?string
    {
        if (preg_match('/\[([^\]]*)\]/', $body, $matches) !== 1) {
            return null;
        }

        return str_replace('\\', '', $matches[1]);
    }

    /**
     * A pattern's body, between its delimiters.
     */
    private static function patternBody(string $pattern): ?string
    {
        return CharacterProof::pattern($pattern)[0] ?? null;
    }

    /**
     * The characters a pattern lets through, for the one shape this understands:
     * a delimited, single, negated character class and nothing else.
     *
     * A bare class is understood. A class followed by anything else is not: a
     * trailing `.` and star deletes from the first invalid character to the end
     * of the string, which is a different and more subtle argument than this one.
     */
    private static function retainedCharacters(string $pattern): ?string
    {
        $parsed = CharacterProof::pattern($pattern);

        if ($parsed === null) {
            return null;
        }

        [$body, $caseless] = $parsed;

        if (! str_starts_with($body, '[^') || ! str_ends_with($body, ']')) {
            return null;
        }

        // A `]` anywhere but the end means the class closed early and there is
        // more pattern after it.
        $inner = substr($body, 2, -1);

        if (str_contains(str_replace('\\]', '', $inner), ']')) {
            return null;
        }

        return CharacterProof::expandClass($inner, $caseless);
    }
}

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
 * The output can only contain characters the class retained. If none of those
 * characters can carry syntax for a given taint kind, that kind is cleared —
 * per kind, never wholesale. `[^0-9]` clears everything; `[^a-zA-Z0-9 ]` clears
 * HTML and SQL but says nothing useful about a value used as a path, because a
 * bare word is still a filename.
 *
 * Everything here fails closed. A pattern that is not a literal, is not a single
 * negated class, uses a construct this does not understand, or carries a flag
 * that changes what the class means, clears nothing and the call stays a
 * propagator.
 */
final class AllowlistPattern
{
    /**
     * Characters that can carry syntax for each taint kind.
     *
     * Deliberately generous. Being wrong in the direction of "this character is
     * dangerous" costs a missed sanitizer and a false positive that a reviewer
     * can dismiss; being wrong the other way launders real taint.
     *
     */
    private const DANGEROUS = [
        'html' => '<>&"\'`/',
        'html_attr' => '<>&"\'`= ',
        // Quotes and escapes end a literal; the rest open comments or stack a
        // second statement.
        'sql' => '\'"`\\;-#/*()',
        'shell' => '`$;|&<>()*?[]{}!\\\'"' . " \n\r\t",
        // A traversal needs a separator or a dot; without either, the value can
        // only ever be one path segment.
        'path' => '/\\.' . "\0",
        // A scheme or an authority is what turns a string into a different URL.
        'url' => ':/\\@?#',
        'header' => "\r\n" . '\\:',
        'eval' => '$();{}[]<>=+-*/\\\'"`,.' . " \n\r\t",
        'unserialize' => ':;{}"\\',
        'ldap' => '()*\\' . "\0",
        'xpath' => '\'"[]()/@=<>*',
    ];

    /**
     * Which taint kinds this call clears, or null when it proves nothing.
     *
     * @param string $pattern     the literal first argument
     * @param string $replacement the literal second argument
     */
    public static function clears(string $pattern, string $replacement): ?TaintSet
    {
        // Checked first, because the CSV shape is an anchored *positive* class
        // and `retainedCharacters()` only understands a negated one — it
        // returns null here, and the allowlist path would leave before asking.
        $csv = self::neutralisesCsvFormulas($pattern, $replacement)
            ? [TaintKind::Csv]
            : [];

        $retained = self::retainedCharacters($pattern);

        if ($retained === null) {
            return $csv === [] ? null : TaintSet::of(...$csv);
        }

        // Whatever is substituted in ends up in the output too, so it is held
        // to the same standard as the characters the class kept.
        $retained .= $replacement;

        $kinds = $csv;

        foreach (self::DANGEROUS as $kind => $dangerous) {
            if (self::sharesNoCharacter($retained, $dangerous)) {
                $taint = TaintKind::tryFrom($kind);

                if ($taint !== null) {
                    $kinds[] = $taint;
                }
            }
        }

        return $kinds === [] ? null : TaintSet::of(...$kinds);
    }

    /**
     * The documented fix for CSV formula injection, recognised.
     *
     * A spreadsheet treats a cell beginning `=`, `+`, `-` or `@` as a formula.
     * Prefixing one with an apostrophe, tab or space stops that, and it is what
     * `wp.output.csv-injection` tells people to do:
     *
     *     $name = preg_replace( '/^([=+\-@])/', "'$1", $row['name'] );
     *
     * Asking for something and then not crediting it when it is done is the
     * same defect as advice that cannot be followed. This is the one shape that
     * counts: anchored at the start, a class covering all four characters, and
     * a replacement that begins with a neutraliser.
     *
     * The character has to be first in the replacement. `$1'` puts the
     * apostrophe *after* the `=`, which neutralises nothing.
     */
    private static function neutralisesCsvFormulas(string $pattern, string $replacement): bool
    {
        if ($replacement === '' || ! str_contains("'\t ", $replacement[0])) {
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
        if (strlen($pattern) < 3) {
            return null;
        }

        $delimiter = $pattern[0];

        if (str_contains('([{< \\', $delimiter) || ctype_alnum($delimiter)) {
            return null;
        }

        $end = strrpos($pattern, $delimiter);

        return $end === false || $end === 0 ? null : substr($pattern, 1, $end - 1);
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
        if (strlen($pattern) < 5) {
            return null;
        }

        $delimiter = $pattern[0];

        // Bracket-style delimiters have their own rules; not worth the risk.
        if (str_contains('([{< \\', $delimiter) || ctype_alnum($delimiter)) {
            return null;
        }

        $end = strrpos($pattern, $delimiter);

        if ($end === false || $end === 0) {
            return null;
        }

        $body = substr($pattern, 1, $end - 1);
        $flags = substr($pattern, $end + 1);

        // `u` changes what a class means for anything above ASCII, `x` changes
        // how whitespace is read, and `m`/`s` are irrelevant but cheap to
        // refuse. Only `i` is understood, by folding case below.
        if ($flags !== '' && $flags !== 'i') {
            return null;
        }

        if (! str_starts_with($body, '[^') || ! str_ends_with($body, ']')) {
            return null;
        }

        // A `]` anywhere but the end means the class closed early and there is
        // more pattern after it.
        $inner = substr($body, 2, -1);

        if (str_contains(str_replace('\\]', '', $inner), ']')) {
            return null;
        }

        $characters = self::expand($inner);

        if ($characters === null) {
            return null;
        }

        return $flags === 'i'
            ? $characters . strtoupper($characters) . strtolower($characters)
            : $characters;
    }

    /**
     * Expand a character class body into the literal characters it names.
     */
    private static function expand(string $inner): ?string
    {
        $out = '';
        $length = strlen($inner);

        for ($i = 0; $i < $length; $i++) {
            $char = $inner[$i];

            if ($char === '\\') {
                $next = $inner[$i + 1] ?? null;

                if ($next === null) {
                    return null;
                }

                $expanded = match ($next) {
                    'd' => '0123456789',
                    'w' => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_',
                    's' => " \t\n\r\v\f",
                    'n' => "\n",
                    'r' => "\r",
                    't' => "\t",
                    // A negated shorthand inside a negated class, a unicode
                    // property, a backreference: all beyond this.
                    'D', 'W', 'S', 'p', 'P', 'b', 'B', 'x', 'u', '0' => null,
                    default => $next,
                };

                if ($expanded === null) {
                    return null;
                }

                $out .= $expanded;
                $i++;

                continue;
            }

            // A range, but not a literal `-` at either end of the class.
            if ($char === '-' && $out !== '' && $i + 1 < $length && $inner[$i + 1] !== ']') {
                $from = $out[strlen($out) - 1];
                $to = $inner[$i + 1];

                if (ord($to) < ord($from)) {
                    return null;
                }

                for ($c = ord($from) + 1; $c <= ord($to); $c++) {
                    $out .= chr($c);
                }

                $i++;

                continue;
            }

            $out .= $char;
        }

        return $out;
    }

    private static function sharesNoCharacter(string $retained, string $dangerous): bool
    {
        $length = strlen($dangerous);

        for ($i = 0; $i < $length; $i++) {
            if (str_contains($retained, $dangerous[$i])) {
                return false;
            }
        }

        return true;
    }
}

<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * Where in a run of HTML a value is about to land.
 *
 * One implementation, two callers with different vantage points: the
 * wrong-context rule reads a statement's literal parts off the AST, and the
 * dataflow sink check reads the literal fragments of a concatenation off SSA.
 * Both are asking the same question of the same kind of text, and two copies
 * of an attribute scanner is how the copies start disagreeing about `<input
 * value=` versus `<input value="`.
 */
final class MarkupPosition
{
    /**
     * Are we inside a `<script>` element, counting only complete tags?
     *
     * The tag has to be *closed* to have opened a script body. A value landing
     * between `<script` and its `>` is in an attribute, and attribute rules
     * apply to it. Counting the bare `<script` called an id and a URL wrong
     * and asked for JavaScript escaping on both.
     */
    public static function inScript(string $before): bool
    {
        $opens = preg_match_all('/<script\b[^>]*>/i', $before);
        $closes = preg_match_all('#</script\s*>#i', $before);

        return $opens > $closes;
    }

    /**
     * Does the text end inside a tag — a `<` opened and not yet closed by `>`?
     */
    public static function insideTag(string $before): bool
    {
        $open = strrpos($before, '<');

        return $open !== false && strpos($before, '>', $open) === false;
    }

    /**
     * The attribute the next value lands in, and whether it is quoted.
     *
     * A forward scan rather than a regex on the tail, because a value often
     * lands part-way through an attribute rather than immediately after the
     * quote:
     *
     *     <button onclick='doThing("   <- still inside onclick
     *
     * Matching `name="` at the end of the text answers no there, and that is
     * the case the wrong-context rule most wants: JavaScript inside an event
     * handler.
     *
     * @return array{0: string, 1: string|null, 2: string}|null the attribute
     *                          name; the quote character holding its value, or
     *                          null if unquoted; and the value text accumulated
     *                          so far — `href="#` has already settled that no
     *                          scheme can follow, and only the text says so
     */
    public static function openAttribute(string $before): ?array
    {
        $inTag = false;
        $name = '';
        $collecting = false;
        $attribute = null;
        $quote = null;
        $openName = null;
        $value = '';
        $length = strlen($before);

        for ($index = 0; $index < $length; $index++) {
            $character = $before[$index];

            if ($quote !== null) {
                if ($character === $quote) {
                    $quote = null;
                    $attribute = null;
                    $value = '';

                    continue;
                }

                $value .= $character;

                continue;
            }

            if (! $inTag) {
                if ($character === '<') {
                    $inTag = true;
                    $name = '';
                    $collecting = true;
                    $attribute = null;
                }

                continue;
            }

            if ($character === '>') {
                $inTag = false;
                $attribute = null;

                continue;
            }

            if ($character === '=') {
                $attribute = strtolower($name);
                $name = '';
                $collecting = false;

                continue;
            }

            if ($character === '"' || $character === "'") {
                if ($attribute !== null) {
                    $quote = $character;
                    $openName = $attribute;
                }

                continue;
            }

            if (ctype_space($character)) {
                // Whitespace ends an unquoted value, and starts the next name.
                $attribute = null;
                $name = '';
                $collecting = true;

                continue;
            }

            if ($collecting) {
                $name .= $character;
            }
        }

        // The quote is still open, so the value lands inside it — whatever else
        // is in there. `onclick='doThing("` is still the onclick attribute, and
        // re-deriving the name with a regex over the tail loses exactly that
        // case, because the tail contains the other quote character.
        if ($quote !== null && $openName !== null) {
            return [$openName, $quote, $value];
        }

        return $inTag && $attribute !== null ? [$attribute, null, ''] : null;
    }
}

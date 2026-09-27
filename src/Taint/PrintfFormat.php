<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * A `sprintf()` format read as the text it writes and the arguments it puts
 * where.
 *
 * `sprintf( "WHERE name = '%s'", esc_sql( $n ) )` quotes its argument exactly
 * as the concatenation would, so it is folded the same way: see
 * {@see SqlQuoteFold}. A numeric conversion writes a number, whatever its
 * argument held.
 */
final class PrintfFormat
{
    /** Conversions that write a number. `%c` writes a character, and is not one. */
    private const NUMERIC = 'bdeEfFgGhHouxX';

    /**
     * The format's pieces in order: literal text, or the position of the
     * argument a `%s` or `%c` writes. A numeric conversion writes digits, so
     * it is text. Null for a format this does not read.
     *
     * @return list<string|int>|null
     */
    public static function pieces(string $format): ?array
    {
        $pieces = [];
        $text = '';
        $next = 0;
        $length = strlen($format);

        for ($index = 0; $index < $length; $index++) {
            $character = $format[$index];

            if ($character !== '%') {
                $text .= $character;

                continue;
            }

            if (($format[$index + 1] ?? null) === '%') {
                $text .= '%';
                $index++;

                continue;
            }

            $specifier = '/\G(?:(\d+)\$)?[-+ 0]*(?:\'.)?\d*(?:\.\d+)?([a-zA-Z])/';

            if (preg_match($specifier, $format, $match, 0, $index + 1) !== 1) {
                return null;
            }

            $index += strlen($match[0]);
            $position = $match[1] !== '' ? (int) $match[1] - 1 : $next++;
            $conversion = $match[2];

            if (str_contains(self::NUMERIC, $conversion)) {
                $text .= '0';

                continue;
            }

            if ($conversion !== 's' && $conversion !== 'c') {
                return null;
            }

            if ($text !== '') {
                $pieces[] = $text;
                $text = '';
            }

            $pieces[] = $position;
        }

        if ($text !== '') {
            $pieces[] = $text;
        }

        return $pieces;
    }
}

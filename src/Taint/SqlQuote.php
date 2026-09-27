<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * Where a position in SQL text sits: bare, inside a quoted literal, or inside
 * a backtick-quoted identifier.
 */
enum SqlQuote
{
    case None;
    case Single;
    case Double;
    case Backtick;
    /** A fragment ended on a backslash, so the next character's role is unknown. */
    case Unknown;

    /**
     * The state after a run of SQL text, and whether the quote open at its
     * start closed inside it.
     *
     * Inside a literal, a backslash escapes the next character and a doubled
     * quote is a quote. Inside backticks, a doubled backtick is a backtick.
     * Comments are not read: a quote in one is rare in a built query.
     *
     * @return array{0: self, 1: bool}
     */
    public function after(string $text): array
    {
        $state = $this;
        $closed = false;
        $length = strlen($text);

        if ($state === self::Unknown) {
            return [$state, false];
        }

        for ($index = 0; $index < $length; $index++) {
            $character = $text[$index];

            if ($state === self::None) {
                $state = match ($character) {
                    "'" => self::Single,
                    '"' => self::Double,
                    '`' => self::Backtick,
                    default => self::None,
                };

                continue;
            }

            if ($state === self::Backtick) {
                if ($character !== '`') {
                    continue;
                }

                if (($text[$index + 1] ?? null) === '`') {
                    $index++;

                    continue;
                }

                $state = self::None;
                $closed = true;

                continue;
            }

            if ($character === '\\') {
                if ($index + 1 >= $length) {
                    return [self::Unknown, $closed];
                }

                $index++;

                continue;
            }

            $quote = $state === self::Single ? "'" : '"';

            if ($character !== $quote) {
                continue;
            }

            if (($text[$index + 1] ?? null) === $quote) {
                $index++;

                continue;
            }

            $state = self::None;
            $closed = true;
        }

        return [$state, $closed];
    }

    public function isLiteral(): bool
    {
        return $this === self::Single || $this === self::Double;
    }
}

<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * Where each part of a concatenation sits in the quotes its own text writes.
 *
 * `esc_sql()` makes a value safe inside quotes and only there, and the quotes
 * are usually added in the same expression that uses it:
 *
 * ```php
 * $clause = " AND name = '" . esc_sql( $n ) . "'";
 * ```
 *
 * By the time `$clause` reaches a query it is one value, and the sink cannot
 * see that its escaped part was quoted. So the concatenation decides. A part
 * carrying {@see TaintKind::SqlUnquoted} inside a quote this concatenation
 * opens and closes is quoted here, and the result carries
 * {@see TaintKind::SqlSelfQuoted} instead: it brings its own quotes. A part
 * carrying `sql_self_quoted` inside quotes or backticks has its own quotes
 * closing the outer ones, and is `sql` again.
 *
 * Backticks work the same way for {@see TaintKind::SqlUnticked}, a value
 * escaped for an identifier: inside backticks the concatenation opens and
 * closes it brings its own, and inside quotes it is `sql` again.
 *
 * Only text the concatenation writes counts: literal fragments, and a part
 * that folds to exactly one string. A part whose text is unknown is taken to
 * hold no quote, the same reading the query-shape check makes. An escaped
 * value holds none it did not escape.
 */
final class SqlQuoteFold
{
    /**
     * The concatenation's own taint, residuals moved to where each part sits.
     *
     * @param list<array{0: string|null, 1: TaintSet}> $parts each part's text when known, and its own taint
     */
    public static function fold(array $parts): TaintSet
    {
        $state = SqlQuote::None;
        $context = [];
        $enclosed = [];
        $inside = [];

        foreach ($parts as $index => [$text, $taint]) {
            unset($taint);

            if ($text === null) {
                $context[$index] = $state;

                if ($state->isLiteral() || $state === SqlQuote::Backtick) {
                    $inside[] = $index;
                }

                continue;
            }

            [$next, $closed] = $state->after($text);
            $open = $state->isLiteral() || $state === SqlQuote::Backtick;

            if ($open && $closed) {
                foreach ($inside as $closedOver) {
                    $enclosed[$closedOver] = $state;
                }
            }

            if (! $open || $closed || $next !== $state) {
                $inside = [];
            }

            $state = $next;
        }

        $result = TaintSet::empty();

        foreach ($parts as $index => [$text, $taint]) {
            if ($text === null) {
                $taint = self::placed($taint, $context[$index] ?? SqlQuote::Unknown, $enclosed[$index] ?? null);
            }

            $result = $result->union($taint);
        }

        return $result;
    }

    /**
     * Whether any of these taints carries a residual the fold can move.
     *
     * @param list<TaintSet> $taints
     */
    public static function applies(array $taints): bool
    {
        foreach ($taints as $taint) {
            if (
                $taint->has(TaintKind::SqlUnquoted)
                || $taint->has(TaintKind::SqlSelfQuoted)
                || $taint->has(TaintKind::SqlUnticked)
            ) {
                return true;
            }
        }

        return false;
    }

    private static function placed(TaintSet $taint, SqlQuote $context, ?SqlQuote $enclosedIn): TaintSet
    {
        if ($context === SqlQuote::Unknown) {
            return $taint;
        }

        if ($taint->has(TaintKind::SqlSelfQuoted) && $context !== SqlQuote::None) {
            $taint = $taint->without(TaintSet::of(TaintKind::SqlSelfQuoted))->with(TaintKind::Sql);
        }

        if ($taint->has(TaintKind::SqlUnquoted) && $enclosedIn !== null && $enclosedIn->isLiteral()) {
            $taint = $taint->without(TaintSet::of(TaintKind::SqlUnquoted))->with(TaintKind::SqlSelfQuoted);
        }

        // Escaped for backticks: quoted by backticks this writes, or as raw as
        // ever inside quotes, where a quote it holds gets out. Bare, the sink
        // decides, since a string this is part of may still open backticks.
        if ($taint->has(TaintKind::SqlUnticked)) {
            if ($enclosedIn === SqlQuote::Backtick) {
                $taint = $taint->without(TaintSet::of(TaintKind::SqlUnticked))->with(TaintKind::SqlSelfQuoted);
            } elseif ($context->isLiteral()) {
                $taint = $taint->without(TaintSet::of(TaintKind::SqlUnticked))->with(TaintKind::Sql);
            }
        }

        return $taint;
    }
}

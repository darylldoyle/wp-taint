<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Operand;

/**
 * What a value can carry, given the characters it can contain.
 *
 * One answer for three places that used to keep their own tables: a strip
 * pattern, `preg_replace( '/[^a-z0-9_]/', '', $v )`; a guard that matches an
 * allowlist, `preg_match( '/^[a-z]+$/', $v )`; and a guard that rejects a
 * denylist, `! preg_match( '/[<>]/', $v )`. The guard used one set for every
 * kind, so rejecting `<` and `>` cleared SQL and shell as well.
 *
 * Each kind clears on its own, when the value cannot contain a character that
 * carries syntax for it. SQL clears in two steps, because whether a character
 * matters depends on the quotes around it. A value with no quote and no
 * backslash cannot leave a quoted literal. Outside quotes, whitespace, a
 * comment, a parenthesis or an operator is enough: `1 OR 1`. So a value with
 * those clears SQL inside quotes only, the way `esc_sql()` does.
 *
 * Two kinds never clear here. Choosing an option or a column by name needs no
 * special character, so a name is still a name (`identifier`). An object id
 * is an authorization question (`object_id`). A check against a fixed list of
 * literals settles the first, and {@see complete()} says so.
 */
final class CharacterProof
{
    /**
     * Characters that carry syntax for each kind.
     *
     * Generous where the kind's context is not known. An `html` sink is any
     * echo, which may be text or an attribute, so both quotes count. `&` does
     * not: a character reference in text or in a quoted attribute is only a
     * character, and `esc_html()` itself passes an existing one through. So
     * `html` asks what `esc_html()` gives, no markup in text and no way out of
     * a quoted attribute. A backtick and `/` do not count either. An
     * `html_attr` sink is always inside a quoted attribute (`applies_by =
     * "quoted_attribute"`), and only a quote ends one.
     */
    private const DANGEROUS = [
        'html' => '<>"\'',
        'html_attr' => '"\'',
        // Characters that end a quoted literal or a quoted identifier.
        'sql' => "'\"`\\\0",
        'shell' => '`$;|&<>()*?[]{}!\\\'"' . " \n\r\t",
        // A traversal needs a separator or a dot; without either, the value can
        // only ever be one path segment.
        'path' => '/\\.' . "\0",
        // A scheme or an authority is what turns a string into a different URL.
        'url' => ':/\\@?#',
        'header' => "\r\n" . '\\:',
        'eval' => '$();{}[]<>=+-*/\\\'"`,.' . " \n\r\t",
        'unserialize' => ':;{}"\\',
        'unserialize_stored' => ':;{}"\\',
        'ldap' => '()*\\' . "\0",
        'xpath' => '\'"[]()/@=<>*',
        // What a spreadsheet reads as the start of a formula.
        'csv' => "=+-@\t\r",
    ];

    /**
     * Characters that let an unquoted SQL value do more than be a value:
     * whitespace and control characters, the comment openers, parentheses and
     * the boolean and comparison operators. `-` is here even without
     * whitespace, because the query supplies it: `"WHERE x = " . $v . " AND
     * owner = 5"` with `$v = '1--'` comments out the owner check. `,` and `.`
     * are not: `1,2,3` and `1.5` stay values.
     */
    private const SQL_OUTSIDE_QUOTES = " \t\n\r\x0B\x0C;#()|&<>=!/*-";

    private function __construct(
        /** The kinds the value cannot carry. */
        public readonly TaintSet $clears,
        /** The value is safe inside SQL quotes only: `sql` becomes `sql_unquoted`. */
        public readonly bool $sqlQuotedOnly,
        /** A fixed list of literals: settles `identifier` too. */
        public readonly bool $complete = false,
        /**
         * Lists the proof holds only while they carry no taint at all. See
         * {@see requiringClean()}.
         *
         * @var list<Operand>
         */
        public readonly array $cleanLists = [],
        /**
         * The value is safe from formulas only in a writer that cannot end a
         * cell early: `csv` becomes `csv_prefixed`. See {@see csvPrefixed()}.
         */
        public readonly bool $csvPrefixOnly = false,
    ) {
    }

    /**
     * This proof, held only while `$list` carries no taint in any part.
     *
     * `in_array( $key, $allowed, true )` makes `$key` one of `$allowed`'s
     * values. When the code built `$allowed` itself, from its own definitions,
     * that is as good as a literal list. Whether the list is clean is a fact
     * about taint, which the guard's structure cannot see and which may change
     * as the analysis learns more, so the proof names the list and whoever
     * applies it checks.
     */
    public function requiringClean(Operand $list): self
    {
        return new self(
            $this->clears,
            $this->sqlQuotedOnly,
            $this->complete,
            [...$this->cleanLists, $list],
            $this->csvPrefixOnly,
        );
    }

    /**
     * A value that can contain only these characters.
     */
    public static function ofCharacters(string $characters): self
    {
        $kinds = [];

        foreach (self::DANGEROUS as $kind => $dangerous) {
            if (strpbrk($characters, $dangerous) === false) {
                $kinds[] = TaintKind::from($kind);
            }
        }

        $clears = TaintSet::of(...$kinds);

        return new self(
            $clears,
            $clears->has(TaintKind::Sql) && self::hasControlOrAny($characters, self::SQL_OUTSIDE_QUOTES),
        );
    }

    /**
     * A value that can contain any character but these.
     */
    public static function ofAllExcept(string $excluded): self
    {
        $characters = '';

        for ($byte = 0; $byte < 256; $byte++) {
            if (! str_contains($excluded, chr($byte))) {
                $characters .= chr($byte);
            }
        }

        return self::ofCharacters($characters);
    }

    /**
     * A value whose first character cannot start a formula: a CSV formula
     * neutraliser put an apostrophe in front of it.
     *
     * Its other characters are as they were, so a writer that lets a quote end
     * the cell early starts a new cell the apostrophe does not cover. The
     * value carries `csv_prefixed` in place of `csv`, and the sink decides.
     */
    public static function csvPrefixed(): self
    {
        return new self(TaintSet::of(TaintKind::Csv), false, false, [], true);
    }

    /**
     * A value that is one of a fixed list of literals the code chose.
     */
    public static function complete(): self
    {
        return new self(TaintSet::allDataflowKinds()->without(TaintSet::of(TaintKind::ObjectId)), false, true);
    }

    /**
     * Whether nothing the value carried survives but an object id.
     */
    public function clearsEverything(): bool
    {
        return $this->complete;
    }

    /**
     * Whether every payload kind is gone, leaving at most a name.
     */
    public function clearsEveryPayload(): bool
    {
        if ($this->sqlQuotedOnly || $this->csvPrefixOnly) {
            return false;
        }

        return self::payloads()->without($this->clears)->isEmpty();
    }

    /**
     * Two guards on one value: each proves what it proves.
     */
    public function and(self $other): self
    {
        $lists = [...$this->cleanLists, ...$other->cleanLists];

        if ($this->complete || $other->complete) {
            $complete = $this->complete ? $this : $other;

            return new self($complete->clears, $complete->sqlQuotedOnly, true, $lists, $complete->csvPrefixOnly);
        }

        $clears = $this->clears->union($other->clears);
        $fullSql = ($this->clears->has(TaintKind::Sql) && ! $this->sqlQuotedOnly)
            || ($other->clears->has(TaintKind::Sql) && ! $other->sqlQuotedOnly);
        $fullCsv = ($this->clears->has(TaintKind::Csv) && ! $this->csvPrefixOnly)
            || ($other->clears->has(TaintKind::Csv) && ! $other->csvPrefixOnly);

        return new self(
            $clears,
            $clears->has(TaintKind::Sql) && ! $fullSql,
            false,
            $lists,
            $clears->has(TaintKind::Csv) && ! $fullCsv,
        );
    }

    /**
     * One of two ways in: only what both prove.
     */
    public function or(self $other): self
    {
        $lists = [...$this->cleanLists, ...$other->cleanLists];

        if ($this->complete && $other->complete) {
            return new self($this->clears, $this->sqlQuotedOnly, true, $lists, $this->csvPrefixOnly);
        }

        $clears = $this->clears->intersect($other->clears);

        return new self(
            $clears,
            $clears->has(TaintKind::Sql) && ($this->sqlQuotedOnly || $other->sqlQuotedOnly),
            false,
            $lists,
            $clears->has(TaintKind::Csv) && ($this->csvPrefixOnly || $other->csvPrefixOnly),
        );
    }

    /**
     * Whether a value with this proof can no longer carry the kind, inside
     * quotes or out.
     */
    public function settles(TaintKind $kind): bool
    {
        // A value that cannot start a formula anywhere cannot start one behind
        // an apostrophe either.
        if ($kind === TaintKind::CsvPrefixed) {
            return $this->clears->has(TaintKind::Csv) && ! $this->csvPrefixOnly;
        }

        return $this->clears->has($kind)
            && ! ($kind === TaintKind::Sql && $this->sqlQuotedOnly)
            && ! ($kind === TaintKind::Csv && $this->csvPrefixOnly);
    }

    /**
     * Whether a value carrying this taint, with this proof, can no longer
     * reach a sink of the kind.
     *
     * A marker is asked of what the proof leaves, because no character names
     * it: `storage` and `unknown` go with the last payload, `escape_voided`
     * with `html`. So digits written to an option settle a stored-write sink.
     * Any other kind is asked of the proof alone, and a proof that holds
     * inside quotes only does not settle an SQL sink: the query may be the
     * value itself.
     */
    public function settlesIn(TaintSet $taint, TaintKind $kind): bool
    {
        if (self::markers()->has($kind)) {
            return ! $this->apply($taint)->has($kind);
        }

        return $this->settles($kind);
    }

    /**
     * What a value carries after this proof.
     *
     * Markers go with the kind they describe: `escaped` and `escape_voided`
     * with `html`. `unknown` and `storage` say where the value came from and
     * whether anyone cleaned it, and a proof that leaves no payload settles
     * both. A name is not a payload here: digits written to an option are not
     * stored XSS, though the same digits can still name an option.
     * `sql_unquoted` stays unless SQL is cleared outright, and so does
     * `csv_prefixed` unless formulas are.
     */
    public function apply(TaintSet $taint): TaintSet
    {
        $removed = $this->clears;

        if ($this->sqlQuotedOnly && $taint->has(TaintKind::Sql)) {
            $taint = $taint->union(TaintSet::of(TaintKind::SqlUnquoted));
        }

        if ($this->clears->has(TaintKind::Sql) && ! $this->sqlQuotedOnly) {
            $removed = $removed->union(TaintSet::of(TaintKind::SqlUnquoted));
        }

        // A value that cannot hold a quote cannot bring its own, and one that
        // cannot hold a backtick or a quote is safe in backticks and out.
        if ($this->clears->has(TaintKind::Sql)) {
            $removed = $removed->union(TaintSet::of(TaintKind::SqlSelfQuoted, TaintKind::SqlUnticked));
        }

        if ($this->clears->has(TaintKind::Html)) {
            $removed = $removed->union(TaintSet::of(TaintKind::Escaped, TaintKind::EscapeVoided));
        }

        if ($this->csvPrefixOnly && $taint->has(TaintKind::Csv)) {
            $taint = $taint->union(TaintSet::of(TaintKind::CsvPrefixed));
        }

        if ($this->clears->has(TaintKind::Csv) && ! $this->csvPrefixOnly) {
            $removed = $removed->union(TaintSet::of(TaintKind::CsvPrefixed));
        }

        $left = $taint->without($removed);
        $payloadLeft = $left->without(self::markers())->without(TaintSet::of(TaintKind::Identifier));

        if ($this->complete || $payloadLeft->isEmpty()) {
            $left = $left->without(TaintSet::of(TaintKind::Unknown, TaintKind::Storage));
        }

        return $left;
    }

    /**
     * The kinds that carry a payload: every dataflow kind but a name, an
     * object id and the storage marker.
     */
    private static function payloads(): TaintSet
    {
        return TaintSet::allDataflowKinds()
            ->without(TaintSet::of(TaintKind::ObjectId, TaintKind::Identifier, TaintKind::Storage));
    }

    /**
     * A delimited pattern's body and modifiers, or null for a shape this does
     * not read: a bracket or alphanumeric delimiter, or a modifier other than
     * `i`, `u`, `D` or `s`.
     *
     * `m` makes `^` and `$` match at every line, so `/^[a-z]+$/m` matches a
     * value with one clean line in it. `x` changes how whitespace in the
     * pattern reads. Anything else is not understood, so it is refused.
     *
     * @return array{0: string, 1: bool}|null the body, and whether it is case-insensitive
     */
    public static function pattern(string $pattern): ?array
    {
        if (strlen($pattern) < 3) {
            return null;
        }

        $delimiter = $pattern[0];

        if (str_contains('([{< \\', $delimiter) || ctype_alnum($delimiter)) {
            return null;
        }

        $end = strrpos($pattern, $delimiter);

        if ($end === false || $end === 0) {
            return null;
        }

        $flags = substr($pattern, $end + 1);

        if (strspn($flags, 'iuDs') !== strlen($flags)) {
            return null;
        }

        return [substr($pattern, 1, $end - 1), str_contains($flags, 'i')];
    }

    /**
     * Every character a class body names, with ranges and the simple escapes
     * expanded. Null for anything else: a nested shorthand, a property, a
     * backreference.
     */
    public static function expandClass(string $inner, bool $caseless = false): ?string
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
                    'D', 'W', 'S', 'p', 'P', 'b', 'B', 'x', 'u', '0', 'h', 'H', 'v', 'V', 'R', 'N' => null,
                    default => ctype_alnum($next) ? null : $next,
                };

                if ($expanded === null) {
                    return null;
                }

                $out .= $expanded;
                $i++;

                continue;
            }

            // A range, but not a literal `-` at either end of the class.
            if ($char === '-' && $out !== '' && $i + 1 < $length) {
                $from = $out[strlen($out) - 1];
                $to = $inner[$i + 1];

                if ($to === '\\' || ord($to) < ord($from)) {
                    return null;
                }

                for ($c = ord($from) + 1; $c <= ord($to); $c++) {
                    $out .= chr($c);
                }

                $i++;

                continue;
            }

            // A POSIX class, `[:alpha:]`, is not expanded.
            if ($char === '[') {
                return null;
            }

            $out .= $char;
        }

        return $caseless ? $out . strtoupper($out) . strtolower($out) : $out;
    }

    private static function markers(): TaintSet
    {
        return TaintSet::of(
            TaintKind::Unknown,
            TaintKind::Storage,
            TaintKind::Escaped,
            TaintKind::EscapeVoided,
            TaintKind::ObjectId,
        );
    }

    private static function hasControlOrAny(string $characters, string $set): bool
    {
        if (strpbrk($characters, $set) !== false) {
            return true;
        }

        $length = strlen($characters);

        for ($i = 0; $i < $length; $i++) {
            $byte = ord($characters[$i]);

            if ($byte < 0x20 || $byte === 0x7F) {
                return true;
            }
        }

        return false;
    }
}

<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * The kinds of taint the engine tracks.
 *
 * Taint is never a boolean. `esc_html()` clears HTML taint and does nothing
 * whatsoever for SQL; `$wpdb->prepare()` clears SQL and nothing else. A boolean
 * model collapses those distinctions and produces an unusable noise machine, so
 * every taint value in this engine is a set over this enum.
 */
enum TaintKind: string
{
    case Html = 'html';
    case HtmlAttr = 'html_attr';
    case Sql = 'sql';
    case Shell = 'shell';
    case Path = 'path';
    case Url = 'url';
    case Header = 'header';
    case Eval = 'eval';
    case Unserialize = 'unserialize';
    case Ldap = 'ldap';
    case Xpath = 'xpath';

    /**
     * A privileged identifier chosen by the request.
     *
     * Distinct from every kind above, because the others describe a context a
     * value is about to be written *into* and this one describes the value
     * naming *what* is written. `update_option( $_POST['name'], $value )` is
     * not an injection: nothing is being escaped wrongly. It is privilege
     * escalation, because `default_role` is an option and `administrator` is a
     * legal value for it.
     *
     * It has its own kind so that no escaper can clear it. esc_html() makes a
     * string safe to print and does nothing to stop it naming an option the
     * caller was never meant to touch, and if this rode on `html` taint an
     * esc_html() anywhere upstream would silence the finding.
     */
    case Identifier = 'identifier';

    /**
     * Escaped for a quoted SQL context, and only for a quoted one.
     *
     * `esc_sql()` escapes quotes and backslashes. Inside quotes that is a real
     * defence; outside them there is nothing to escape, and `1 OR 1=1` reaches
     * the database whole:
     *
     * ```php
     * $wpdb->get_row( "SELECT * FROM t WHERE name = '" . esc_sql( $n ) . "'" );  // fine
     * $wpdb->get_row( "SELECT * FROM t WHERE ID = " . esc_sql( $id ) );          // not
     * ```
     *
     * So the quote-escapers do not simply clear `sql`; they trade it for this,
     * which the sink reports only when the value lands outside quotes. Modelling
     * it as a kind rather than as a check at the sink is what keeps it narrow: a
     * table name from a helper method never carried SQL taint, so it never picks
     * this up, and the hundreds of `"SELECT ... FROM {$table}"` in the corpus
     * stay quiet.
     */
    case SqlUnquoted = 'sql_unquoted';

    /**
     * Not a taint kind at all: nothing seeds it and nothing propagates it.
     *
     * Structural rules report broken authorization, which has no dataflow to
     * describe. Giving those findings a category here keeps `Finding` a single
     * shape across both halves of the tool. `RegistryLoader` rejects it
     * anywhere a real taint kind is expected, so it cannot leak into the
     * dataflow engine by accident.
     */
    case Authz = 'authz';

    /**
     * Stable bit position, used by the bitmask inside {@see TaintSet}.
     *
     * Declared explicitly rather than derived from declaration order, so that
     * reordering the cases above can never silently change a serialised value.
     */
    public function bit(): int
    {
        return match ($this) {
            self::Html => 1 << 0,
            self::HtmlAttr => 1 << 1,
            self::Sql => 1 << 2,
            self::Shell => 1 << 3,
            self::Path => 1 << 4,
            self::Url => 1 << 5,
            self::Header => 1 << 6,
            self::Eval => 1 << 7,
            self::Unserialize => 1 << 8,
            self::Ldap => 1 << 9,
            self::Xpath => 1 << 10,
            self::Identifier => 1 << 12,
            self::SqlUnquoted => 1 << 13,
            self::Authz => 1 << 11,
        };
    }

    /**
     * True for everything the dataflow engine may propagate.
     */
    public function isDataflowKind(): bool
    {
        return $this !== self::Authz;
    }

    /**
     * True for a kind nothing may seed — only the engine derives it.
     *
     * {@see self::SqlUnquoted} exists solely because a quote-escaper ran, and
     * the whole rule resting on it is "this value was escaped for quotes it did
     * not get". Seeding it means claiming that of a value no escaper touched.
     *
     * That is not hypothetical. Summarising a function seeds a parameter with
     * every kind at once, so `bulk_add( $payment_id, $meta )` in WPForms had
     * `$meta` carrying `sql_unquoted` on arrival, and the standard bulk-insert
     * idiom — `implode()` of `prepare()`d tuples interpolated into an INSERT —
     * was reported as SQL injection. The pinned corpus baseline caught it as a
     * single moved count on one plugin.
     */
    public function isDerived(): bool
    {
        return $this === self::SqlUnquoted;
    }

    /**
     * Every kind that may be seeded and propagated, in declaration order.
     *
     * Excludes the derived kinds, so "taint this with everything" cannot
     * manufacture a claim only an escaper is allowed to make.
     *
     * @return list<self>
     */
    public static function dataflowKinds(): array
    {
        return array_values(array_filter(
            self::cases(),
            static fn (self $kind): bool => $kind->isDataflowKind() && ! $kind->isDerived(),
        ));
    }

    /**
     * Human-readable label used in trace step descriptions.
     */
    public function label(): string
    {
        return match ($this) {
            self::Html => 'HTML',
            self::HtmlAttr => 'HTML attribute',
            self::Sql => 'SQL',
            self::Shell => 'shell command',
            self::Path => 'filesystem path',
            self::Url => 'URL',
            self::Header => 'HTTP header',
            self::Eval => 'evaluated code',
            self::Unserialize => 'serialised payload',
            self::Ldap => 'LDAP filter',
            self::Xpath => 'XPath expression',
            self::Identifier => 'privileged identifier',
            self::SqlUnquoted => 'SQL outside quotes',
            self::Authz => 'authorization',
        };
    }
}

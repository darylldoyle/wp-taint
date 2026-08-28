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
     * Object injection reachable only through data already in the database.
     *
     * The same sink as {@see self::Unserialize} and a different bar to clear.
     * A request reaching `unserialize()` is exploitable by anyone who can send
     * the request; stored data reaching it needs an attacker who can first
     * write that option, that meta or that row.
     *
     * Both are real — three CVEs in the pinned set are stored object injection,
     * and the escalation from a subscriber-level meta write to RCE through a
     * POP chain is the classic WordPress version of this bug. But WordPress
     * reads its own serialised meta constantly, and calling 91 corpus findings
     * `critical` alongside the 12 that need no preconditions at all devalues
     * the word for both.
     */
    case UnserializeStored = 'unserialize_stored';

    /**
     * This value has been through an output escaper.
     *
     * Not a taint. A marker, carried so that {@see self::EscapeVoided} can tell
     * a value that was escaped and then handed on from one that was never
     * escaped at all. Nothing reports it.
     */
    case Escaped = 'escaped';

    /**
     * Escaped, and then passed through a filter before it was printed.
     *
     * ```php
     * $title = esc_html( $_GET['title'] );
     * echo apply_filters( 'acme_title', $title );
     * ```
     *
     * The escaping is void. Any plugin may hook `acme_title` and return
     * whatever it likes, and this one prints the result. That is why the
     * practice is called *late* escaping: it has to be the last thing that
     * happens to a value, because every step afterwards is another chance to
     * undo it.
     *
     * Invisible to a plain taint model, which sees the escaper clear the taint
     * and nothing put it back. This engine reported nothing at all on the four
     * lines above until this kind existed.
     */
    case EscapeVoided = 'escape_voided';

    /**
     * A spreadsheet formula waiting to be opened.
     *
     * A CSV cell beginning `=`, `+`, `-` or `@` is executed as a formula when
     * the file is opened in Excel or Sheets, which turns an exported user
     * field into code running on the reviewer's machine (CWE-1236).
     *
     * Its own kind because no HTML escaper touches it: `esc_html()` leaves
     * `=cmd|...` exactly as it found it, and would be the wrong tool even if it
     * did. The neutraliser is a prefix — a quote, a space, a tab — and nothing
     * in the escaping catalogue does that.
     */
    case Csv = 'csv';

    /**
     * Where this value came from, nobody here can say.
     *
     * A parameter of a function no caller in the scan reaches; the result of a
     * callee the engine cannot follow. The engine's standing answer for those
     * has been *clean* — a documented false negative, on the grounds that an
     * undocumented false positive is worse.
     *
     * That answer costs more than it looked. Two third-party suites score the
     * output half of this tool at 0.18 recall on exactly it:
     *
     * ```php
     * function fx_render_bad( $value ) {   // "assumed tainted (option, meta, query var)"
     *     echo $value;                     // ruleid: wp.output.unescaped
     * ```
     *
     * WordPress's own standard is sanitise on input and escape on output — two
     * obligations, each owed wherever the value came from. Treating unknown as
     * clean answers a question nobody asked: not "is this value dangerous" but
     * "can I prove it is". This kind is the third state, so the difference
     * between *proven clean* and *not known* stops being invisible.
     *
     * Any sanitizer or escaper clears it, because applying one settles the
     * question either way.
     */
    case Unknown = 'unknown';

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
            self::UnserializeStored => 1 << 14,
            self::Escaped => 1 << 15,
            self::EscapeVoided => 1 << 16,
            self::Csv => 1 << 17,
            self::Unknown => 1 << 18,
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
        return in_array($this, [self::SqlUnquoted, self::Escaped, self::EscapeVoided, self::Unknown], true);
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
            self::UnserializeStored => 'stored serialised payload',
            self::Escaped => 'escaped',
            self::EscapeVoided => 'escaping voided by a filter',
            self::Csv => 'spreadsheet formula',
            self::Unknown => 'unknown provenance',
            self::Authz => 'authorization',
        };
    }
}

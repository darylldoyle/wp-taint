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
     * Every kind the dataflow engine may propagate, in declaration order.
     *
     * @return list<self>
     */
    public static function dataflowKinds(): array
    {
        return array_values(array_filter(self::cases(), static fn (self $kind): bool => $kind->isDataflowKind()));
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
            self::Authz => 'authorization',
        };
    }
}

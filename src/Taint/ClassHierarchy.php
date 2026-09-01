<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\ParsedFile;
use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Which class extends which, and who uses which trait, across the whole scan.
 *
 * Method lookup was flat — `Class::method`, exactly as written — so a method
 * inherited from a parent never resolved, and neither did one brought in by a
 * trait. Gravity Forms hits the first shape on every page: `RGFormsModel
 * extends GFFormsModel`, the table-name helpers live on the parent, and every
 * `RGFormsModel::get_lead_meta_table_name()` was a call the engine could not
 * see into, so the `$wpdb->prefix . 'rg_lead_meta'` it returns was an
 * unaccounted value interpolated into a query.
 *
 * {@see lookupOrder} answers "where would PHP find this method?" as a list of
 * class names in PHP's own precedence order: the class's own methods win over
 * its traits' methods, and a trait's methods win over the parent's. A trait
 * inside a trait is expanded in place. The walk stops at a parent the scan has
 * no definition for — `extends WP_List_Table` ends the chain, and the call
 * stays unresolved rather than guessed at.
 *
 * ## What is deliberately not modelled
 *
 * `use T { m as n; insteadof }` aliasing and conflict resolution: the first
 * trait declaring the method wins, in declaration order, which is what PHP does
 * when no `insteadof` says otherwise. A class relying on `insteadof` picks the
 * same body only by luck, so a project using it heavily may see a method
 * resolve to the other trait — conservative reviewers can find it, and the
 * spelling is rare enough in the plugin corpus that modelling it would be
 * complexity nothing exercises.
 *
 * Interfaces carry no bodies and contribute nothing to method lookup, so they
 * are not recorded.
 */
final class ClassHierarchy
{
    /**
     * Linearizations do not get long in plugin code; the cap exists for a
     * cyclic `extends` chain, which PHP would refuse to load but a scan of
     * broken code still has to survive.
     */
    private const MAX_ANCESTRY = 32;

    /** @var array<string, string> class => parent it extends */
    private array $parents = [];

    /** @var array<string, list<string>> class or trait => traits it uses, in declaration order */
    private array $traits = [];

    /**
     * Classes already recorded, so a duplicate declaration cannot append its
     * traits to the first one's list. First wins, deterministically, exactly
     * as duplicate functions are handled.
     *
     * @var array<string, true>
     */
    private array $seen = [];

    /**
     * Linearizations, memoized. The index is read millions of times during
     * analysis and written only while files are being added, so the cache is
     * dropped on every observation and never goes stale.
     *
     * @var array<string, list<string>>
     */
    private array $orders = [];

    /**
     * Read every class, trait and enum declaration in a file.
     *
     * Must run while the AST is still held, like {@see DeclaredTypes}.
     */
    public function observeFile(ParsedFile $file): void
    {
        $this->orders = [];

        foreach ((new NodeFinder())->findInstanceOf($file->ast(), Node\Stmt\ClassLike::class) as $node) {
            if (! $node instanceof Node\Stmt\ClassLike || ! isset($node->namespacedName)) {
                continue;
            }

            $name = self::normalize($node->namespacedName->toString());

            if (isset($this->seen[$name])) {
                continue;
            }

            $this->seen[$name] = true;

            if ($node instanceof Node\Stmt\Class_ && $node->extends instanceof Node\Name) {
                $this->parents[$name] = self::normalize($node->extends->toString());
            }

            foreach ($node->getTraitUses() as $use) {
                foreach ($use->traits as $trait) {
                    $this->traits[$name][] = self::normalize($trait->toString());
                }
            }
        }
    }

    /**
     * The class this one extends, or null when it extends nothing the scan saw
     * declared. Normalized lowercase, matching function-table keys.
     */
    public function parentOf(string $class): ?string
    {
        return $this->parents[self::normalize($class)] ?? null;
    }

    /**
     * Every class and trait a method call on `$class` could land in, in PHP's
     * precedence order: the class itself, then its traits, then the parent,
     * the parent's traits, and so on up the chain.
     *
     * @return list<string> normalized lowercase names, starting with `$class`
     */
    public function lookupOrder(string $class): array
    {
        $start = self::normalize($class);

        if (isset($this->orders[$start])) {
            return $this->orders[$start];
        }

        $order = [];
        $queued = [];
        $current = $start;

        while ($current !== null && ! isset($queued[$current]) && count($order) < self::MAX_ANCESTRY) {
            $queued[$current] = true;
            $order[] = $current;
            $this->expandTraits($current, $order, $queued);
            $current = $this->parents[$current] ?? null;
        }

        return $this->orders[$start] = $order;
    }

    /**
     * A class's traits, and their traits, in declaration order.
     *
     * @param list<string>        $order
     * @param array<string, true> $queued
     */
    private function expandTraits(string $owner, array &$order, array &$queued): void
    {
        foreach ($this->traits[$owner] ?? [] as $trait) {
            if (isset($queued[$trait]) || count($order) >= self::MAX_ANCESTRY) {
                continue;
            }

            $queued[$trait] = true;
            $order[] = $trait;
            $this->expandTraits($trait, $order, $queued);
        }
    }

    private static function normalize(string $name): string
    {
        return strtolower(ltrim($name, '\\'));
    }
}

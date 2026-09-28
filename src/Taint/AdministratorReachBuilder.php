<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\IncludeGraph;
use Enshrined\WpTaint\Registry\Matcher;
use Enshrined\WpTaint\Registry\Registry;
use PHPCfg\Block;
use PHPCfg\Op;

/**
 * Decides which functions only an administrator can reach, once, before the
 * fixed point.
 *
 * Who can reach a function is a property of every path to it, not of its
 * body. A helper that saves the settings is administrator-only when each of
 * its callers is, or calls it behind a check.
 *
 * ```php
 * function acme_save( $values ) { update_option( 'acme', $values ); }
 *
 * function acme_settings_page() { acme_save( $_POST ); }   // a manage_options page
 *
 * add_action( 'wp_ajax_acme_save', function () {
 *     if ( ! current_user_can( 'manage_options' ) ) {
 *         wp_die();
 *     }
 *     acme_save( $_POST );                                  // behind the check
 * } );
 * ```
 *
 * One open caller is enough to make it open. Called from a `wp_ajax_nopriv_`
 * handler as well, the helper can be reached by anyone.
 *
 * ## How it is decided
 *
 * The graph is the call graph, hook dispatches included. It adds an edge from
 * each include or template site to the file it loads, because that file's
 * top-level code has no other caller. Only the functions on some path to an
 * option write are walked: the writers and everything that reaches them.
 *
 * A function nothing in the scan calls is an entry point: a template, a
 * plugin's main file, a REST route's callback, an admin page's. So is every
 * hook callback, whatever else calls it. WordPress or another plugin can fire
 * its hook, and a dispatch in the scan does not show that nothing else does.
 * An entry point is open unless WordPress runs it only for an administrator:
 * an admin page registered with a site-wide grant, or a REST route callback
 * whose every route's permission callback requires one. Openness then spreads
 * along every edge whose sites are not all behind a site-wide check in the
 * caller. What it never reaches is administrator-only.
 *
 * The walk counts only the callers the graph can see, the way
 * {@see \Enshrined\WpTaint\Scan\Scanner} carries a REST route's entitlement
 * into its callees. A group of functions that call only each other has no
 * entry point the scan can see. Something outside the scan calls it, so it is
 * open.
 */
final class AdministratorReachBuilder
{
    private readonly CapabilityGuard $guard;

    public function __construct(
        private readonly Registry $registry,
        private readonly CallGraph $callGraph,
        private readonly CallResolver $resolver,
        private readonly FunctionBodies $bodies,
        private readonly ?IncludeGraph $includes,
    ) {
        $this->guard = CapabilityGuard::siteWide($registry, $callGraph);
    }

    /**
     * @param list<FunctionMeta>  $functions every function in the scan
     * @param list<string>        $writers   the calls whose reach is decided, as call graph identities
     * @param array<string, true> $entries   function keys WordPress runs only for an administrator
     * @param array<string, true> $hooked    function keys registered on a hook, which WordPress can run
     *                                       whatever else calls them
     */
    public function build(array $functions, array $writers, array $entries, array $hooked = []): AdministratorReach
    {
        $wanted = array_flip($writers);

        /** @var array<string, array<string, true>> $callers callee => callers */
        $callers = [];

        /** @var list<string> $writing */
        $writing = [];

        foreach ($functions as $function) {
            foreach ($this->callGraph->calleesOf($function->key) as $callee) {
                $callers[$callee][$function->key] = true;
            }

            foreach ($this->callGraph->externalsOf($function->key) as $identity) {
                if (isset($wanted[$identity])) {
                    $writing[] = $function->key;
                }
            }
        }

        foreach ($this->includes?->includedFiles() ?? [] as $file) {
            foreach ($this->includes?->includersOf($file) ?? [] as $includer) {
                $callers[strtolower($file . '::{main}')][$includer] = true;
            }
        }

        $closure = self::closure($writing, $callers);

        /** @var array<string, list<string>> $calleesIn caller => its callees in the closure */
        $calleesIn = [];

        foreach (array_keys($closure) as $key) {
            foreach (array_keys($callers[$key] ?? []) as $caller) {
                $calleesIn[$caller][] = $key;
            }
        }

        $guarded = $this->guardedCallees($functions, $calleesIn);

        // A group of functions that call only each other has no caller the
        // scan can see, so it is an entry point too.
        $reached = self::spread(
            array_keys(array_filter(
                $closure,
                static fn (string $key): bool => ($callers[$key] ?? []) === []
                    || isset($entries[$key])
                    || isset($hooked[$key]),
                ARRAY_FILTER_USE_KEY,
            )),
            $calleesIn,
        );

        $open = self::spread(
            array_keys(array_filter(
                $closure,
                static fn (string $key): bool => ! isset($reached[$key])
                    || isset($hooked[$key])
                    || (($callers[$key] ?? []) === [] && ! isset($entries[$key])),
                ARRAY_FILTER_USE_KEY,
            )),
            $calleesIn,
            $guarded,
        );

        return new AdministratorReach(array_diff_key($closure, $open));
    }

    /**
     * The writers and every function that reaches one.
     *
     * @param list<string>                       $writers
     * @param array<string, array<string, true>> $callers
     *
     * @return array<string, true>
     */
    private static function closure(array $writers, array $callers): array
    {
        $closure = array_fill_keys($writers, true);
        $queue = $writers;

        while ($queue !== []) {
            $key = array_pop($queue);

            foreach (array_keys($callers[$key] ?? []) as $caller) {
                if (! isset($closure[$caller])) {
                    $closure[$caller] = true;
                    $queue[] = $caller;
                }
            }
        }

        return $closure;
    }

    /**
     * Everything reachable from the seeds, crossing no edge `$blocked` holds.
     *
     * @param list<string>                       $seeds
     * @param array<string, list<string>>        $calleesIn
     * @param array<string, array<string, true>> $blocked caller => callees not to cross into
     *
     * @return array<string, true>
     */
    private static function spread(array $seeds, array $calleesIn, array $blocked = []): array
    {
        $reached = array_fill_keys($seeds, true);
        $queue = $seeds;

        while ($queue !== []) {
            $caller = array_pop($queue);

            foreach ($calleesIn[$caller] ?? [] as $callee) {
                if (isset($reached[$callee]) || isset($blocked[$caller][$callee])) {
                    continue;
                }

                $reached[$callee] = true;
                $queue[] = $callee;
            }
        }

        return $reached;
    }

    /**
     * For each caller, the callees it reaches only from blocks a site-wide
     * check dominates, in every body declared under its key.
     *
     * A body with no such block, which is most of them, is answered without
     * resolving a single call. The bodies are fetched in the order the scan
     * lists them, file by file, so a file the memory budget does not hold is
     * rebuilt once.
     *
     * @param list<FunctionMeta>          $functions
     * @param array<string, list<string>> $calleesIn caller => its callees in the closure
     *
     * @return array<string, array<string, true>> caller => callees reached only behind a check
     */
    private function guardedCallees(array $functions, array $calleesIn): array
    {
        /** @var array<string, array<string, true>> $behind */
        $behind = [];

        /** @var array<string, array<string, true>> $around */
        $around = [];

        /** @var array<string, true> $unchecked callers with a body no check is in */
        $unchecked = [];

        $callers = array_values(array_filter(
            $functions,
            static fn (FunctionMeta $function): bool => isset($calleesIn[$function->key]),
        ));

        foreach (new BodySweep($this->bodies, $callers) as $context) {
            $key = $context->key;

            if (isset($unchecked[$key])) {
                continue;
            }

            $blocks = BlockOrder::of($context->func->cfg);
            $this->guard->forFunction($blocks);

            /** @var array<int, true> $checked */
            $checked = [];

            foreach ($blocks as $block) {
                if ($this->guard->isEntitled($block)) {
                    $checked[spl_object_id($block)] = true;
                }
            }

            // Every site in this body is open, so no callee can be reached
            // only behind a check, whatever another body under the key does.
            if ($checked === []) {
                $unchecked[$key] = true;

                continue;
            }

            $callees = array_flip($calleesIn[$key] ?? []);

            foreach ($this->sites($context, $blocks) as [$block, $keys]) {
                $isChecked = isset($checked[spl_object_id($block)]);

                foreach ($keys as $callee) {
                    if (! isset($callees[$callee])) {
                        continue;
                    }

                    if ($isChecked) {
                        $behind[$key][$callee] = true;
                    } else {
                        $around[$key][$callee] = true;
                    }
                }
            }
        }

        $guarded = [];

        foreach (array_keys($behind) as $caller) {
            if (! isset($unchecked[$caller])) {
                $guarded[$caller] = array_diff_key($behind[$caller], $around[$caller] ?? []);
            }
        }

        return $guarded;
    }

    /**
     * Every site in a body that reaches another function, with the block it
     * is in and the keys it reaches: calls, hook dispatches, includes and
     * template loads.
     *
     * The include and template sites are numbered the way
     * {@see \Enshrined\WpTaint\Cfg\IncludeGraphBuilder} numbered them, so the
     * graph's answer for each is the one the analysis gets.
     *
     * @param list<Block> $blocks
     *
     * @return list<array{0: Block, 1: list<string>}>
     */
    private function sites(FunctionContext $context, array $blocks): array
    {
        $types = new ClassTypeMap();
        $file = $context->file->relativePath;
        $includeOffset = 0;
        $templateOffset = 0;
        $sites = [];

        foreach ($blocks as $block) {
            foreach ($block->children as $op) {
                if (! $op instanceof Op\Expr) {
                    continue;
                }

                $keys = [];
                $loaded = [];

                if ($op instanceof Op\Expr\Include_) {
                    $loaded = $this->includes?->targetsFor(
                        IncludeGraph::siteKey($file, $op->getLine(), $includeOffset++),
                    ) ?? [];
                } elseif (
                    ($op instanceof Op\Expr\FuncCall || $op instanceof Op\Expr\NsFuncCall)
                    && $this->loadsTemplate($op)
                ) {
                    $loaded = $this->includes?->targetsFor(
                        IncludeGraph::templateSiteKey($file, $op->getLine(), $templateOffset++),
                    ) ?? [];
                }

                foreach ($loaded as $target) {
                    $keys[] = strtolower($target . '::{main}');
                }

                foreach ($this->resolver->resolveAll($op, $context, $types) as $target) {
                    if ($target->userFunctionKey !== null) {
                        $keys[] = $target->userFunctionKey;
                    }
                }

                if ($keys !== []) {
                    $sites[] = [$block, $keys];
                }
            }
        }

        return $sites;
    }

    private function loadsTemplate(Op\Expr\FuncCall|Op\Expr\NsFuncCall $op): bool
    {
        $names = $op instanceof Op\Expr\NsFuncCall
            ? [OperandHelper::literalString($op->nsName), OperandHelper::literalString($op->name)]
            : [OperandHelper::literalString($op->name)];

        foreach ($names as $name) {
            if ($name !== null && $this->registry->templateLoader(Matcher::function($name)) !== null) {
                return true;
            }
        }

        return false;
    }
}

<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Scan;

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Cfg\ConstantTableBuilder;
use Enshrined\WpTaint\Cfg\IncludeGraphBuilder;
use Enshrined\WpTaint\Cfg\IncludeResolver;
use Enshrined\WpTaint\Cfg\ParseError;
use Enshrined\WpTaint\Cfg\ThemeRoots;
use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\FindingCollection;
use Enshrined\WpTaint\Hooks\HookGraphBuilder;
use Enshrined\WpTaint\Hooks\RestRouteCollector;
use Enshrined\WpTaint\Hooks\RestRouteTable;
use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Rules\RuleContext;
use Enshrined\WpTaint\Rules\StructuralRule;
use Enshrined\WpTaint\Rules\Wordpress\BypassableNonceCheck;
use Enshrined\WpTaint\Rules\Wordpress\GuardWithoutExit;
use Enshrined\WpTaint\Rules\Wordpress\MetaCapabilityWithoutObject;
use Enshrined\WpTaint\Rules\Wordpress\MissingAdminPostCapabilityCheck;
use Enshrined\WpTaint\Rules\Wordpress\MissingAjaxCapabilityCheck;
use Enshrined\WpTaint\Rules\Wordpress\MissingRestPermissionCallback;
use Enshrined\WpTaint\Rules\Wordpress\NonceWithoutAction;
use Enshrined\WpTaint\Rules\Wordpress\SettingWithoutSanitizeCallback;
use Enshrined\WpTaint\Rules\Wordpress\WrongContextEscape;
use Enshrined\WpTaint\Support\CycleCollector;
use Enshrined\WpTaint\Support\PathHelper;
use Enshrined\WpTaint\Taint\AnalysisOptions;
use Enshrined\WpTaint\Taint\AnalysisWarning;
use Enshrined\WpTaint\Taint\BodySweep;
use Enshrined\WpTaint\Taint\CallableResolver;
use Enshrined\WpTaint\Taint\CallGraph;
use Enshrined\WpTaint\Taint\CallGraphBuilder;
use Enshrined\WpTaint\Taint\CallResolver;
use Enshrined\WpTaint\Taint\CapabilityGuard;
use Enshrined\WpTaint\Taint\FunctionBodies;
use Enshrined\WpTaint\Taint\FunctionMeta;
use Enshrined\WpTaint\Taint\InterproceduralResolver;
use Enshrined\WpTaint\Taint\IntraproceduralAnalyzer;
use Enshrined\WpTaint\Taint\ReceiverResolver;
use Enshrined\WpTaint\Taint\SummaryExtractor;
use Enshrined\WpTaint\Taint\TaintGraphWriter;
use Enshrined\WpTaint\Taint\UserFunctionTable;
use Enshrined\WpTaint\Taint\ValueResolver;

/**
 * The pipeline.
 *
 *   parse → summaries to a fixed point → per-function findings →
 *   structural rules → sort, de-duplicate
 *
 * Deliberately whole-program: interprocedural taint crosses files, so every
 * file is parsed before any analysis begins.
 */
final class Scanner
{
    /** @var list<StructuralRule> */
    private readonly array $structuralRules;

    /**
     * Superseded rule id => the rules that supersede it at the same location.
     * An empty list means any other finding at that location supersedes it.
     *
     */
    private const RULE_PRECEDENCE = [
        'wp.sqli.unprepared-query' => [],
        'wp.sqli.wpdb-query' => ['wp.sqli.prepare-non-literal'],
        // Both say "this escaper does not protect this attribute"; the traced
        // finding also says where the value came from, so it wins the line.
        'wp.xss.wrong-context-escape' => ['wp.xss.unescaped-attribute'],
        // The unescaped-output family tells one story at three levels of
        // certainty about the same echo. "Unknown" says the escaping could not
        // be determined; "unescaped-output" says it is definitely absent;
        // "escape-voided" says an escaper ran and something undid it. The more
        // specific finding names the real defect and its fix, so it supersedes
        // the vaguer ones at the same line rather than the reader triaging all
        // three.
        'wp.output.unescaped-unknown' => ['wp.xss.unescaped-output', 'wp.xss.escape-voided'],
        'wp.xss.unescaped-output' => ['wp.xss.escape-voided'],
    ];

    public function __construct(
        private readonly Registry $registry,
        private readonly AnalysisOptions $options,
        private readonly string $root,
        private readonly bool $structuralRulesEnabled = true,
        private readonly ?string $taintGraphPath = null,
        private readonly int $jobs = 1,
        /**
         * Trees parsed and summarised for their symbols, but never reported on.
         *
         * A Composer dependency's helper, or WordPress core itself. Without
         * them an unmodelled call is routine rather than rare; with them the
         * engine knows what those functions do to the values passed through,
         * and the reader is not shown findings in code they did not write and
         * cannot fix.
         *
         * @var list<string>
         */
        private readonly array $includePaths = [],
        /**
         * Where to report phase changes. Silent unless the caller says
         * otherwise — see {@see NullScanProgress}.
         */
        private readonly ScanProgress $progress = new NullScanProgress(),
        /**
         * Bytes of parsed files the scan may hold, or null for no limit. A file
         * it does not hold is rebuilt from source whenever it is needed again,
         * which costs time and changes nothing else. Zero rebuilds every time,
         * which is how the tests prove that. See {@see FunctionBodies}.
         */
        private readonly ?int $memoryBudget = null,
    ) {
        // Structural rules are pure AST shape checks over one file. They exist
        // for the bugs that are an absence — a missing capability check, a
        // missing sanitize_callback — which no amount of following values will
        // find. The query-shape check that used to live here needs the dataflow
        // verdict, so it moved into the engine as
        // {@see \Enshrined\WpTaint\Taint\QueryShapeInspector}.
        $this->structuralRules = [
            new MissingRestPermissionCallback(),
            new MissingAjaxCapabilityCheck(),
            new MissingAdminPostCapabilityCheck(),
            new NonceWithoutAction(),
            new MetaCapabilityWithoutObject(),
            new BypassableNonceCheck(),
            new GuardWithoutExit(),
            new WrongContextEscape(),
            new SettingWithoutSanitizeCallback(),
        ];
    }

    /**
     * @param list<string> $files absolute paths, already sorted
     */
    public function scan(array $files): ScanResult
    {
        // PHP's own collector spends most of a large scan walking graphs that
        // are still in use. This one collects when the heap has grown instead;
        // see {@see CycleCollector}.
        $collector = new CycleCollector();
        $collector->start();

        try {
            return $this->scanFiles($files, $collector);
        } finally {
            $collector->stop();
        }
    }

    /**
     * @param list<string> $files
     */
    private function scanFiles(array $files, CycleCollector $collector): ScanResult
    {
        $startedAt = hrtime(true);

        $builder = new CfgBuilder($this->root);
        $functions = new UserFunctionTable();

        // Every body the scan analyses comes from here: held while the budget
        // allows, rebuilt from source when it does not. Nothing else keeps a
        // parsed file. See docs/design/two-pass-engine.md.
        $bodies = new FunctionBodies($builder, $this->processBudget(), $collector);

        /** @var list<string> $parsedPaths every file that parsed, scanned first, for the theme roots */
        $parsedPaths = [];

        /** @var list<string> $scannedPaths scanned files that parsed, for the structural rules */
        $scannedPaths = [];

        /** @var list<ParseError> $parseErrors */
        $parseErrors = [];

        $scanned = [];

        // Each scanned file is indexed as soon as it is parsed, in the order
        // the files were given, which is the order the symbol table saw them
        // in when every file was parsed first and indexed afterwards.
        $this->progress->phase('Parsing', count($files));

        foreach ($files as $file) {
            $this->progress->advance();
            $result = $builder->buildFromFile($file);

            if (! $result->isSuccess()) {
                // Never skipped, never swallowed. A file we cannot read is a
                // reported error and sets exit code 2.
                $parseErrors[] = $result->error();

                continue;
            }

            $parsedFile = $result->file();
            $functions->addFile($parsedFile);
            $parsedPaths[] = $parsedFile->path;
            $scannedPaths[] = $parsedFile->path;
            $scanned[$parsedFile->relativePath] = true;

            // Offered with its AST, which the structural rules read later. A
            // file the budget cannot hold is rebuilt for them then.
            $bodies->add($parsedFile);
        }

        // Reference trees, parsed after the real ones so a file appearing in
        // both is analysed as the user's own.
        $referenceParseFailures = 0;

        /** @var array<string, true> $reference */
        $reference = [];

        // Announced before the walk, not after it. Finding the files in a
        // reference tree is itself a directory crawl over someone's whole
        // plugins directory, and reporting it only once it finished left the
        // slow half silent.
        if ($this->includePaths !== []) {
            $this->progress->phase('Finding reference files', null);
        }

        $referenceFiles = $this->referenceFiles($scanned);

        if ($referenceFiles !== []) {
            $this->progress->phase('Parsing reference trees', count($referenceFiles));
        }

        foreach ($referenceFiles as $file) {
            $this->progress->advance();

            $result = $builder->buildFromFile($file);

            // A reference tree is context, not a deliverable. A file in it that
            // will not parse is a gap in what we know about the dependency, not
            // an error in the code being scanned, so it is counted rather than
            // failing the run.
            if (! $result->isSuccess()) {
                $referenceParseFailures++;

                continue;
            }

            // Indexed and stripped of its AST straight away. Indexing is the
            // only thing that reads a reference file's AST, since structural
            // rules skip reference trees, and the AST is about 40% of a parsed
            // file.
            $parsedFile = $result->file();
            $functions->addFile($parsedFile);
            $parsedFile->releaseAst();
            $bodies->add($parsedFile);

            $parsedPaths[] = $parsedFile->path;
            $reference[$parsedFile->relativePath] = true;
        }

        unset($result, $parsedFile);

        $ruleContext = new RuleContext();

        /** @var list<Finding> $findings */
        $findings = [];

        $receivers = new ReceiverResolver($functions->declaredTypes());
        $metas = $functions->all();

        // The builders below each walk every function once, or twice for the
        // constants. Each walk is a sweep: a body the budget does not hold is
        // rebuilt when reached, and each file at most once per sweep.
        $contexts = new BodySweep($bodies, $metas);

        // Constants first: WordPress builds include paths out of them and
        // almost nothing else, so resolution stops dead without this, and
        // everything downstream wants a resolver that can see them.
        // Which theme each file belongs to, so `get_template_directory()` and
        // the constant chains themes hang off it fold. From the scanned file
        // list, reference trees included — a theme referenced for context still
        // answers the question for its own files.
        $themes = ThemeRoots::fromFiles($parsedPaths);

        $static = (new ConstantTableBuilder(new ValueResolver(themes: $themes)))->buildBoth($contexts);
        $values = (new ValueResolver(themes: $themes))->withConstants($static['constants'], $static['returns']);
        $callables = new CallableResolver($this->registry, $functions, $values);

        // The hook and call graphs are built before the structural rules run,
        // because the authorization rules walk them: "does this AJAX callback
        // reach a capability check, through however many helpers" is a
        // call-graph question, not a shape one.
        // No total: these two builders walk every op of every function and
        // reporting a count would mean threading progress through both. A bar
        // that fills in one jump is worse than a sentence that stays put.
        $this->progress->phase('Building the hook and call graphs', null);

        // One sweep for everything that needs only the constants: hook
        // registrations, include sites and REST routes. They were three
        // sweeps, and under a budget every sweep rebuilds every file the cache
        // does not hold. None of the three reads another's result, and none
        // keeps state between functions beyond its own graph, so building them
        // side by side gives what building them one after another did. The
        // call graph needs the finished hook graph, so it is a sweep of its
        // own.
        $hookBuilder = new HookGraphBuilder($callables, $values, $receivers);
        $includeBuilder = $this->options->followIncludes
            ? new IncludeGraphBuilder(
                new IncludeResolver($values, $files, $this->root, $themes),
                $this->root,
                $this->registry,
                $values,
            )
            : null;
        $routeCollector = new RestRouteCollector($callables, $receivers);

        foreach ($contexts as $context) {
            $hookBuilder->accept($context);
            $includeBuilder?->accept($context);
            $routeCollector->accept($context);
        }

        unset($context);
        $hooks = $hookBuilder->finish();
        $includes = $includeBuilder?->finish();
        $routeTable = $routeCollector->finish();

        $callGraph = (new CallGraphBuilder($this->registry, $functions, $values, $receivers, $callables, $hooks))
            ->build($contexts);
        $ruleContext = $ruleContext->withGraphs($callGraph, $hooks)
            ->withDeclaredTypes($functions->declaredTypes())
            ->withFunctionTable($functions);

        // A registration we could not place is a hook edge we know exists and
        // cannot draw. Counted next to the other coverage gaps rather than
        // guessed at.
        foreach ($hooks->unplaced() as $registration) {
            $ruleContext->recordUnresolvedHook(
                'add_action/add_filter',
                $registration->file,
                $registration->line,
                sprintf(
                    'hook name could not be resolved, so %s is not connected to any dispatch',
                    $registration->callback->name(),
                ),
            );
        }

        $this->progress->phase('Structural rules', count($scannedPaths));

        foreach ($scannedPaths as $path) {
            $this->progress->advance();
            // Structural rules are pure AST shape checks over one file, so they
            // run before the whole-program taint pass, which is what lets the
            // AST go early. Reference trees are skipped: a missing
            // permission_callback in WordPress core is not this project's bug
            // to fix.
            if ($this->structuralRulesEnabled) {
                $file = $bodies->fileWithAst($path);

                foreach ($this->structuralRules as $rule) {
                    $findings = [...$findings, ...$rule->analyse($file, $this->registry, $ruleContext)];
                }
            }

            $bodies->releaseAst($path);
        }

        unset($file);

        $resolver = new CallResolver(
            $this->registry,
            $functions,
            $callables,
            $values,
            $receivers,
            $hooks,
        );
        $restRoutes = $this->restRoutes($routeTable, $functions, $bodies, $callGraph);

        $analyzer = new IntraproceduralAnalyzer(
            $this->registry,
            $functions,
            $resolver,
            $this->options,
            $includes,
            $callGraph,
            $hooks->shortcodeCallbackKeys(),
            $hooks->printedReturnCallbacks(),
            $restRoutes,
        );
        $extractor = new SummaryExtractor($analyzer, $this->options);
        $analysed = $bodies;

        $interprocedural = new InterproceduralResolver(
            $analyzer,
            $extractor,
            $this->options,
            $this->jobs,
            $callGraph,
            $analysed,
        );

        $this->progress->note($this->describeCache('after setup', $bodies));
        $resolution = $interprocedural->resolve($metas, $this->progress);
        $this->progress->note($this->describeCache('after resolution', $bodies));

        // Findings a structural rule could not decide alone. The rule recorded
        // what it would emit and which callback settles it; the summary — which
        // only now exists — gives the verdict. A callback the scan never
        // summarised drops the finding, because absence proves nothing.
        foreach ($ruleContext->deferredFindings() as $deferred) {
            $summary = $resolution['summaries']->get($ruleContext->canonicalCallbackKey($deferred['callbackKey']));

            if ($summary === null) {
                continue;
            }

            if ($summary->returnTaintFor(0)->intersect($deferred['survivesKinds'])->isEmpty()) {
                continue;
            }

            $findings[] = $deferred['finding'];
        }

        /** @var list<AnalysisWarning> $warnings */
        $warnings = [];

        if (! $resolution['converged']) {
            $warnings[] = new AnalysisWarning(
                '',
                '',
                sprintf(
                    'Interprocedural summaries did not converge within %d rounds. Some cross-function flows may be '
                        . 'missing.',
                    $this->options->maxInterproceduralRounds,
                ),
            );
        }

        $referenceCallers = $this->referenceCallersOfScannedCode($metas, $callGraph, $reference);

        // No total: with --jobs the work happens in the workers, which cannot
        // report back to this bar.
        $this->progress->phase('Collecting findings', null);

        // A graph dump needs the live taint state, which cannot cross a process
        // boundary, so it forces the serial path.
        $graph = $this->taintGraphPath === null ? null : new TaintGraphWriter();
        $pool = new WorkerPool($graph === null ? $this->jobs : 1);

        /** @var list<array{findings: list<Finding>, warnings: list<AnalysisWarning>}> $shards */
        $shards = $pool->run(
            static function (
                int $shard,
                int $shardCount
            ) use (
                $metas,
                $analysed,
                $analyzer,
                $resolution,
                $graph,
                $reference,
                $referenceCallers,
            ): array {
                $shardFindings = [];
                $shardWarnings = [];

                // A contiguous run of the functions, not every Nth one. They
                // are listed file by file, so striping made every worker
                // rebuild every file the cache does not hold. A run keeps each
                // file with one worker, and merged in shard order the runs
                // give the warnings in exactly the order one process does.
                $first = intdiv(count($metas) * $shard, $shardCount);
                $last = intdiv(count($metas) * ($shard + 1), $shardCount);

                foreach ($metas as $index => $meta) {
                    if ($index < $first || $index >= $last) {
                        continue;
                    }

                    // A reference tree has already done its job: its summaries
                    // are in the table and its symbols are known. Walking it
                    // again for findings would report bugs in code the reader
                    // did not write and cannot fix, and cost the time of a
                    // second whole-program pass to do it.
                    //
                    // Except where it calls into the scanned code. A plugin's
                    // `do_action()` is the caller of the scanned callback, so
                    // the callback is not an entry point and its parameters are
                    // not seeded. The flow is reported while analysing the
                    // caller, at the sink inside the callee, and skipping the
                    // caller lost the finding altogether.
                    $isReference = isset($reference[$meta->relativePath]);

                    if ($isReference && ! isset($referenceCallers[$meta->key])) {
                        continue;
                    }

                    $context = $analysed->context($meta);
                    $result = $analyzer->analyze(
                        $context,
                        $resolution['summaries'],
                        $resolution['properties'],
                        $resolution['scopes'],
                        null,
                        true,
                    );

                    // From a reference caller, only what lands in scanned code.
                    // Its warnings are about code the reader cannot change.
                    if ($isReference) {
                        foreach ($result->findings as $finding) {
                            if (! isset($reference[$finding->file])) {
                                $shardFindings[] = $finding;
                            }
                        }

                        continue;
                    }

                    $shardFindings = [...$shardFindings, ...$result->findings];
                    $shardWarnings = [...$shardWarnings, ...$result->warnings];

                    if ($graph !== null && $result->state !== null) {
                        $graph->addFunction($context, $result->state);
                    }
                }

                return ['findings' => $shardFindings, 'warnings' => $shardWarnings];
            },
        );

        // Merged in shard order; FindingCollection sorts afterwards, so the
        // result is identical whatever --jobs was.
        foreach ($shards as $shardResult) {
            $findings = [...$findings, ...$shardResult['findings']];
            $warnings = [...$warnings, ...$shardResult['warnings']];
        }

        $this->progress->note($this->describeCache('after findings', $bodies));

        if ($graph !== null && $this->taintGraphPath !== null) {
            file_put_contents($this->taintGraphPath, $graph->render());
        }

        $collection = FindingCollection::fromArray($findings)
            ->withRulePrecedence(self::RULE_PRECEDENCE);

        $unresolvedHooks = array_map(
            static fn (object $hook): string => (string) $hook->describe(),
            $ruleContext->unresolvedHooks(),
        );

        // An include or template call the engine could not follow is a hole in
        // the analysis exactly as large as the file behind it. The graph has
        // recorded these since includes were first followed; nothing was
        // reporting them, which made the gap invisible — the one thing this
        // tool is not allowed to do with a gap.
        foreach ($includes?->unresolved() ?? [] as $site) {
            $unresolvedHooks[] = sprintf('%s:%d  include — %s', $site['file'], $site['line'], $site['reason']);
        }

        sort($unresolvedHooks);

        return new ScanResult(
            $collection,
            $parseErrors,
            count($scannedPaths),
            $warnings,
            $this->root,
            $this->registry->names,
            $this->options->interprocedural,
            (int) round((hrtime(true) - $startedAt) / 1_000_000),
            $unresolvedHooks,
            referenceFiles: count($reference),
            referenceParseFailures: $referenceParseFailures,
        );
    }

    /**
     * The graph cache's share of the budget in this process.
     *
     * Workers fork from this process and start with its cache, so a budget
     * held whole here would be held again in every worker as soon as it read
     * the pages. Each process gets an equal part instead, and the scan's cache
     * stays near the budget whatever --jobs is.
     */
    private function processBudget(): ?int
    {
        if ($this->memoryBudget === null || $this->jobs <= 1) {
            return $this->memoryBudget;
        }

        return intdiv($this->memoryBudget, $this->jobs);
    }

    private function describeCache(string $when, FunctionBodies $bodies): string
    {
        $budget = $this->processBudget();
        $megabytes = static fn (int $bytes): string => number_format($bytes / 1_048_576) . 'MB';

        return sprintf(
            'graph cache %s: %s held of %s, a pool of %s, %d files rebuilt in this process',
            $when,
            $megabytes($bodies->held()),
            $budget === null ? 'no limit' : $megabytes($budget - $bodies->poolBudget()),
            $megabytes($bodies->poolBudget()),
            $bodies->rebuilds(),
        );
    }

    /**
     * Every REST route, and which callbacks their permission callbacks entitle.
     *
     * A callback is entitled when every route it handles has a permission
     * callback, every body that callback resolves to allows a request only
     * behind an entitling check, and none of it is a function the scan cannot
     * see into. `__return_true`, a callback that will not resolve, and a route
     * with no permission callback all leave it unentitled.
     *
     */
    private function restRoutes(
        RestRouteTable $table,
        UserFunctionTable $functions,
        FunctionBodies $bodies,
        CallGraph $callGraph,
    ): RestRouteTable {
        $guard = new CapabilityGuard($this->registry, $callGraph);

        foreach ($table->callbackKeys() as $key) {
            $entitled = true;

            foreach ($table->routesFor($key) as $route) {
                if ($route->permission === null || $route->permission === []) {
                    $entitled = false;

                    break;
                }

                foreach ($route->permission as $permission) {
                    $meta = $permission->dynamic || $permission->userFunctionKey === null
                        ? null
                        : $functions->get($permission->userFunctionKey);

                    if ($meta === null || ! $guard->permitsOnlyWhenEntitled($bodies->context($meta))) {
                        $entitled = false;

                        break 2;
                    }
                }
            }

            if ($entitled) {
                $table->markEntitled($key);
            }
        }

        $this->entitleCallees($table, $functions->all(), $callGraph);

        return $table;
    }

    /**
     * Carry a route's entitlement into what its callback calls.
     *
     * WordPress checked the permission before the callback ran, so it holds in
     * every function the callback calls, and in theirs: a controller method
     * that reads `$request['id']` itself, called from the closure registered as
     * the route's callback, is as entitled as the closure. A function counts
     * once every caller the call graph knows of is entitled; one with no known
     * caller is an entry point in its own right and does not.
     *
     * On the suppressing side, like the rest of the authorization rules: a
     * caller the graph cannot see, a callable it could not resolve, is not a
     * caller here.
     *
     * @param list<FunctionMeta> $functions
     */
    private function entitleCallees(RestRouteTable $table, array $functions, CallGraph $callGraph): void
    {
        /** @var array<string, array<string, true>> $callers */
        $callers = [];

        foreach ($functions as $function) {
            foreach ($callGraph->calleesOf($function->key) as $callee) {
                $callers[$callee][$function->key] = true;
            }
        }

        do {
            $changed = false;

            foreach ($callers as $key => $from) {
                if ($table->isEntitled($key)) {
                    continue;
                }

                $all = true;

                foreach (array_keys($from) as $caller) {
                    if ($caller === $key || ! $table->isEntitled($caller)) {
                        $all = false;

                        break;
                    }
                }

                if ($all) {
                    $table->markEntitled($key);
                    $changed = true;
                }
            }
        } while ($changed);
    }

    /**
     * Reference functions that call into the scanned code, directly or through
     * other reference functions.
     *
     * Walked upward from every scanned function, so a chain such as a form
     * handler calling a helper that fires `do_action()` is found whole: the
     * handler holds the argument taint, and the helper's summary carries the
     * sink in the scanned callback back up to it.
     *
     * @param list<FunctionMeta>  $functions
     * @param array<string, true> $reference relative paths of reference files
     *
     * @return array<string, true> function keys
     */
    private function referenceCallersOfScannedCode(array $functions, CallGraph $callGraph, array $reference): array
    {
        if ($reference === []) {
            return [];
        }

        /** @var array<string, list<string>> $callers */
        $callers = [];

        /** @var array<string, bool> $isReference function key => declared in a reference file */
        $isReference = [];

        foreach ($functions as $function) {
            $isReference[$function->key] ??= isset($reference[$function->relativePath]);

            foreach ($callGraph->calleesOf($function->key) as $callee) {
                $callers[$callee][] = $function->key;
            }
        }

        $queue = [];

        foreach ($isReference as $key => $inReference) {
            if (! $inReference) {
                $queue[] = $key;
            }
        }

        $found = [];

        while ($queue !== []) {
            $key = array_pop($queue);

            foreach ($callers[$key] ?? [] as $caller) {
                if (($isReference[$caller] ?? false) && ! isset($found[$caller])) {
                    $found[$caller] = true;
                    $queue[] = $caller;
                }
            }
        }

        return $found;
    }

    /**
     * Files under `--include-path`, minus anything already being scanned.
     *
     * A path in both is the user's own code, and analysed as such: findings in
     * it are reported.
     *
     * @param array<string, true> $scanned relative paths already parsed
     *
     * @return list<string>
     */
    private function referenceFiles(array $scanned): array
    {
        if ($this->includePaths === []) {
            return [];
        }

        $files = [];

        // No default excludes. `vendor/` is skipped when deciding what to
        // report on, and `--include-path=./vendor` is the whole point of this
        // flag — a finder that quietly drops it would find nothing and say so
        // by producing no findings, which is the worst way to be wrong.
        foreach ((new FileFinder([], false))->find($this->includePaths) as $path) {
            if (! isset($scanned[PathHelper::relative($path, $this->root)])) {
                $files[] = $path;
            }
        }

        return $files;
    }
}

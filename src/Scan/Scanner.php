<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Scan;

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Cfg\ConstantTableBuilder;
use Enshrined\WpTaint\Cfg\IncludeGraphBuilder;
use Enshrined\WpTaint\Cfg\IncludeResolver;
use Enshrined\WpTaint\Cfg\ParsedFile;
use Enshrined\WpTaint\Cfg\ParseError;
use Enshrined\WpTaint\Cfg\ThemeRoots;
use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\FindingCollection;
use Enshrined\WpTaint\Hooks\HookGraphBuilder;
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
use Enshrined\WpTaint\Support\PathHelper;
use Enshrined\WpTaint\Taint\AnalysisOptions;
use Enshrined\WpTaint\Taint\AnalysisWarning;
use Enshrined\WpTaint\Taint\CallableResolver;
use Enshrined\WpTaint\Taint\CallGraphBuilder;
use Enshrined\WpTaint\Taint\CallResolver;
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
        $startedAt = hrtime(true);

        $builder = new CfgBuilder($this->root);

        /** @var list<ParsedFile> $parsed */
        $parsed = [];

        /** @var list<ParseError> $parseErrors */
        $parseErrors = [];

        $this->progress->phase('Parsing', count($files));

        foreach ($files as $file) {
            $this->progress->advance();
            $result = $builder->buildFromFile($file);

            if ($result->isSuccess()) {
                $parsed[] = $result->file();

                continue;
            }

            // Never skipped, never swallowed. A file we cannot read is a
            // reported error and sets exit code 2.
            $parseErrors[] = $result->error();
        }

        // Reference trees, parsed after the real ones so a file appearing in
        // both is analysed as the user's own.
        $referenceParseFailures = 0;
        $scanned = [];

        foreach ($parsed as $file) {
            $scanned[$file->relativePath] = true;
        }

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

            $parsed[] = $result->file();
            $reference[$result->file()->relativePath] = true;
        }

        $this->progress->phase('Indexing symbols', count($parsed));
        $functions = new UserFunctionTable();
        $ruleContext = new RuleContext();

        /** @var list<Finding> $findings */
        $findings = [];

        foreach ($parsed as $file) {
            $this->progress->advance();
            $functions->addFile($file);
        }

        $receivers = new ReceiverResolver($functions->declaredTypes());
        $contexts = $functions->all();

        // Constants first: WordPress builds include paths out of them and
        // almost nothing else, so resolution stops dead without this, and
        // everything downstream wants a resolver that can see them.
        // Which theme each file belongs to, so `get_template_directory()` and
        // the constant chains themes hang off it fold. From the scanned file
        // list, reference trees included — a theme referenced for context still
        // answers the question for its own files.
        $themes = ThemeRoots::fromFiles(array_map(static fn (ParsedFile $file): string => $file->path, $parsed));

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
        $hooks = (new HookGraphBuilder($callables, $values, $receivers))->build($contexts);
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

        $this->progress->phase('Structural rules', count($parsed));

        foreach ($parsed as $file) {
            $this->progress->advance();
            // Structural rules are pure AST shape checks over one file, so they
            // run before the whole-program taint pass — which is what lets the
            // AST go early.
            // Reference trees are skipped: a missing permission_callback in
            // WordPress core is not this project's bug to fix.
            // Reference trees are skipped: a missing permission_callback in
            // WordPress core is not this project's bug to fix.
            if ($this->structuralRulesEnabled && ! isset($reference[$file->relativePath])) {
                foreach ($this->structuralRules as $rule) {
                    $findings = [...$findings, ...$rule->analyse($file, $this->registry, $ruleContext)];
                }
            }

            $file->releaseAst();
        }

        $resolver = new CallResolver(
            $this->registry,
            $functions,
            $callables,
            $values,
            $receivers,
            $hooks,
        );
        // Include sites resolve before analysis, like the hook graph: which
        // file an include loads is a static fact.
        $includes = $this->options->followIncludes
            ? (new IncludeGraphBuilder(
                new IncludeResolver($values, $files, $this->root, $themes),
                $this->root,
                $this->registry,
                $values,
            ))->build($contexts)
            : null;

        $analyzer = new IntraproceduralAnalyzer(
            $this->registry,
            $functions,
            $resolver,
            $this->options,
            $includes,
            $callGraph,
            $hooks->shortcodeCallbackKeys(),
            $hooks->printedReturnCallbacks(),
        );
        $extractor = new SummaryExtractor($analyzer, $this->options);
        $interprocedural = new InterproceduralResolver($analyzer, $extractor, $this->options, $this->jobs);

        $resolution = $interprocedural->resolve($contexts, $this->progress);

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
                $contexts,
                $analyzer,
                $resolution,
                $graph,
                $reference,
            ): array {
                $shardFindings = [];
                $shardWarnings = [];

                foreach ($contexts as $index => $context) {
                    if ($index % $shardCount !== $shard) {
                        continue;
                    }

                    // A reference tree has already done its job: its summaries
                    // are in the table and its symbols are known. Walking it
                    // again for findings would report bugs in code the reader
                    // did not write and cannot fix, and cost the time of a
                    // second whole-program pass to do it.
                    if (isset($reference[$context->file->relativePath])) {
                        continue;
                    }

                    $result = $analyzer->analyze(
                        $context,
                        $resolution['summaries'],
                        $resolution['properties'],
                        $resolution['scopes'],
                        null,
                        true,
                    );

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
            count($parsed) - count($reference),
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

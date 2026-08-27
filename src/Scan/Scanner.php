<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Scan;

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Cfg\ParsedFile;
use Enshrined\WpTaint\Cfg\ParseError;
use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\FindingCollection;
use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Rules\RuleContext;
use Enshrined\WpTaint\Rules\StructuralRule;
use Enshrined\WpTaint\Rules\Wordpress\MissingAjaxCapabilityCheck;
use Enshrined\WpTaint\Rules\Wordpress\MissingRestPermissionCallback;
use Enshrined\WpTaint\Taint\AnalysisOptions;
use Enshrined\WpTaint\Taint\AnalysisWarning;
use Enshrined\WpTaint\Taint\CallResolver;
use Enshrined\WpTaint\Taint\InterproceduralResolver;
use Enshrined\WpTaint\Taint\IntraproceduralAnalyzer;
use Enshrined\WpTaint\Taint\SummaryExtractor;
use Enshrined\WpTaint\Taint\TaintGraphWriter;
use Enshrined\WpTaint\Taint\UserFunctionTable;

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
    ) {
        // Both remaining structural rules are pure AST shape checks. The
        // query-shape check that used to live here needs the dataflow verdict,
        // so it moved into the engine as
        // {@see \Enshrined\WpTaint\Taint\QueryShapeInspector}.
        $this->structuralRules = [
            new MissingRestPermissionCallback(),
            new MissingAjaxCapabilityCheck(),
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

        foreach ($files as $file) {
            $result = $builder->buildFromFile($file);

            if ($result->isSuccess()) {
                $parsed[] = $result->file();

                continue;
            }

            // Never skipped, never swallowed. A file we cannot read is a
            // reported error and sets exit code 2.
            $parseErrors[] = $result->error();
        }

        $functions = new UserFunctionTable();
        $ruleContext = new RuleContext();

        /** @var list<Finding> $findings */
        $findings = [];

        foreach ($parsed as $file) {
            $functions->addFile($file);

            // Structural rules are pure AST shape checks, so they can run the
            // moment a file is parsed — which is what lets the AST go before
            // the whole-program taint pass starts.
            if ($this->structuralRulesEnabled) {
                foreach ($this->structuralRules as $rule) {
                    $findings = [...$findings, ...$rule->analyse($file, $this->registry, $ruleContext)];
                }
            }

            $file->releaseAst();
        }

        $resolver = new CallResolver($this->registry, $functions);
        $analyzer = new IntraproceduralAnalyzer($this->registry, $functions, $resolver, $this->options);
        $extractor = new SummaryExtractor($analyzer, $this->options);
        $interprocedural = new InterproceduralResolver($analyzer, $extractor, $this->options, $this->jobs);

        $contexts = $functions->all();
        $resolution = $interprocedural->resolve($contexts);

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
            static function (int $shard, int $shardCount) use ($contexts, $analyzer, $resolution, $graph): array {
                $shardFindings = [];
                $shardWarnings = [];

                foreach ($contexts as $index => $context) {
                    if ($index % $shardCount !== $shard) {
                        continue;
                    }

                    $result = $analyzer->analyze(
                        $context,
                        $resolution['summaries'],
                        $resolution['properties'],
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

        return new ScanResult(
            $collection,
            $parseErrors,
            count($parsed),
            $warnings,
            $this->root,
            $this->registry->names,
            $this->options->interprocedural,
            (int) round((hrtime(true) - $startedAt) / 1_000_000),
            $unresolvedHooks,
        );
    }
}

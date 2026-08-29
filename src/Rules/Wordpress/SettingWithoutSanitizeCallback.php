<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules\Wordpress;

use Enshrined\WpTaint\Cfg\ParsedFile;
use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Rules\AstHelper;
use Enshrined\WpTaint\Rules\RuleContext;
use Enshrined\WpTaint\Rules\StructuralRule;
use PhpParser\Node;

/**
 * A Settings API option registered with nothing to clean what is posted into it.
 *
 * ```php
 * register_setting( 'acme_group', 'acme_headline' );
 * ```
 *
 * `options.php` writes whatever arrives for a registered setting. The
 * `sanitize_callback` is the only thing between the request and the option, and
 * omitting it stores the POST body verbatim — which is stored XSS the moment
 * anything renders it, and is why WordPress added the argument.
 *
 * ## Why this is structural
 *
 * There is no flow to follow. The request never appears in the plugin's code:
 * core reads `$_POST`, core writes the option, and the plugin's only
 * involvement is the registration that told core to do it. Taint analysis
 * cannot find an absence, which is the same reason the authorization rules are
 * structural.
 *
 * ## What it will not claim
 *
 * An options array it cannot read. A registration whose arguments are built
 * conditionally, spread, or handed in through a variable is recorded as
 * unresolved rather than guessed at, because a wrong answer here is either a
 * stored-XSS hole reported or missed.
 *
 * A `sanitize_callback` that is present but useless — `'__return_true'`, or a
 * callback that returns its argument — is accepted. Judging what a named
 * callback does is the call graph's job and belongs in a separate rule.
 */
final class SettingWithoutSanitizeCallback implements StructuralRule
{
    private const RULE = 'wp.input.setting-without-sanitize';

    private const REGISTRAR = 'register_setting';

    /**
     * The argument holding the options array.
     *
     * `register_setting( $group, $name, $args )`. The pre-4.7 signature passed
     * a callable here instead, and a plugin still using it has named something
     * to clean the value, so a non-array third argument is accepted.
     */
    private const OPTIONS_ARGUMENT = 2;

    public function id(): string
    {
        return self::RULE;
    }

    /**
     * @return list<Finding>
     */
    public function analyse(ParsedFile $file, Registry $registry, RuleContext $context): array
    {
        $findings = [];

        foreach (AstHelper::findAll($file->ast(), Node\Expr\FuncCall::class) as $call) {
            if (! $call instanceof Node\Expr\FuncCall) {
                continue;
            }

            $name = AstHelper::functionName($call);

            if ($name === null || strtolower($name) !== self::REGISTRAR) {
                continue;
            }

            $finding = $this->inspect($call, $file, $registry, $context);

            if ($finding !== null) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }

    private function inspect(
        Node\Expr\FuncCall $call,
        ParsedFile $file,
        Registry $registry,
        RuleContext $context,
    ): ?Finding {
        $options = AstHelper::argument($call, self::OPTIONS_ARGUMENT);

        if ($options !== null && ! $options instanceof Node\Expr\Array_) {
            // The old callable signature, or an array built elsewhere. Either
            // way this rule cannot read it and says so rather than guessing.
            $context->recordUnresolvedHook(
                self::REGISTRAR,
                $file->relativePath,
                $call->getStartLine(),
                'setting arguments are not a literal array',
            );

            return null;
        }

        if ($options instanceof Node\Expr\Array_) {
            if (AstHelper::hasDynamicKeys($options)) {
                $context->recordUnresolvedHook(
                    self::REGISTRAR,
                    $file->relativePath,
                    $call->getStartLine(),
                    'setting arguments contain dynamic or spread keys',
                );

                return null;
            }

            if (AstHelper::hasArrayKey($options, 'sanitize_callback')) {
                return null;
            }
        }

        return StructuralFinding::at(
            $call,
            $file,
            $registry,
            self::RULE,
            Severity::Medium,
            'This setting has no sanitize_callback, so options.php stores whatever is posted for it '
                . 'without cleaning it first.',
            self::REGISTRAR,
        );
    }
}

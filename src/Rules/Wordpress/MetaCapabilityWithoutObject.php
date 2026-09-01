<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules\Wordpress;

use Enshrined\WpTaint\Cfg\ParsedFile;
use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Registry\CapabilityScope;
use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Rules\AstHelper;
use Enshrined\WpTaint\Rules\RuleContext;
use Enshrined\WpTaint\Rules\StructuralRule;
use PhpParser\Node;

/**
 * An object capability checked with no object.
 *
 * `edit_post`, `delete_post`, `edit_user` and their relatives are meta
 * capabilities: `map_meta_cap()` resolves them *against a specific row* — this
 * post's author, this post's status, this user — which is what makes them the
 * correct check in front of an object operation. Called without the id there
 * is no row to resolve against:
 *
 * ```php
 * if ( current_user_can( 'edit_post' ) ) {          // checks nothing about any post
 *     wp_update_post( [ 'ID' => $_POST['id'], … ] );
 * }
 * ```
 *
 * WordPress 6.1 added a `_doing_it_wrong` notice for exactly this call shape,
 * which is a development-time nudge and not a defence: the call still returns,
 * and what it returns is decided by fallback behaviour rather than by the
 * object the code is about to touch. Either way the check reads as object
 * authorization and is not one, which is worth a finding even where the
 * fallback happens to deny.
 *
 * Only literal capabilities in the catalogue's object scope fire. A computed
 * capability could be anything; a plugin's own capability follows the plugin's
 * own model; and the role-scoped plurals (`edit_posts`) are a different,
 * dataflow-shaped question that `wp.authz.object-id-from-request` asks.
 */
final class MetaCapabilityWithoutObject implements StructuralRule
{
    private const RULE = 'wp.authz.meta-cap-without-object';

    /**
     * Function name => [capability argument, object argument].
     *
     * From core's signatures: `current_user_can( $capability, $object )`, the
     * others take a user, blog or post first.
     */
    private const CHECKERS = [
        'current_user_can' => [0, 1],
        'user_can' => [1, 2],
        'author_can' => [1, 2],
        'current_user_can_for_blog' => [1, 2],
    ];

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

            if ($name === null || ! isset(self::CHECKERS[$name])) {
                continue;
            }

            [$capabilityArgument, $objectArgument] = self::CHECKERS[$name];
            $capability = AstHelper::stringValue(AstHelper::argument($call, $capabilityArgument));

            if (
                $capability === null
                || $registry->capabilityScope($capability) !== CapabilityScope::Object
                || AstHelper::argument($call, $objectArgument) !== null
            ) {
                continue;
            }

            $findings[] = StructuralFinding::at(
                $call,
                $file,
                $registry,
                self::RULE,
                Severity::Medium,
                sprintf(
                    "%s( '%s' ) names a meta capability and no object. map_meta_cap() resolves '%s' against a "
                        . 'specific post, comment, term or user, so without the id the call checks nothing about '
                        . 'the row this code is about to touch. Pass the id as the next argument.',
                    $name,
                    $capability,
                    $capability,
                ),
                $name . ':' . $capability,
            );
        }

        return $findings;
    }
}

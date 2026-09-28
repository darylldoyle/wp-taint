<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Hooks;

use Enshrined\WpTaint\Taint\BlockOrder;
use Enshrined\WpTaint\Taint\CallableResolver;
use Enshrined\WpTaint\Taint\ClassTypeMap;
use Enshrined\WpTaint\Taint\FunctionContext;
use Enshrined\WpTaint\Taint\OperandHelper;
use Enshrined\WpTaint\Taint\ReceiverResolver;
use Enshrined\WpTaint\Taint\ValueResolver;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Reads every admin page registration into an {@see AdminPageTable}, with the
 * capability each page asks for: `add_menu_page()`, `add_submenu_page()` and
 * the `add_*_page()` wrappers.
 *
 * WP File Manager registers its preferences screen like this.
 *
 *     add_submenu_page( 'wp_file_manager', …, 'manage_options',
 *         'wp_file_manager_preferences', array( &$this, 'wp_file_manager_root' ) );
 *
 * That callback saves the plugin's settings. Only a user who holds
 * `manage_options` gets that far. The registration is the page's whole access
 * control, and nothing in the callback's body says so.
 *
 * On the control flow graph, like {@see RestRouteCollector}, so the callback
 * resolves through the same {@see CallableResolver} every other callable does.
 * A page whose callback will not resolve is left out: its body keeps whatever
 * other callers it has.
 */
final class AdminPageCollector
{
    /**
     * Registrar => [capability argument, callback argument], from core's
     * signatures. The `add_*_page()` wrappers each add a submenu to one
     * top-level menu and share a signature.
     */
    private const REGISTRARS = [
        'add_menu_page' => [2, 4],
        'add_submenu_page' => [3, 5],
        'add_object_page' => [2, 4],
        'add_utility_page' => [2, 4],
        'add_management_page' => [2, 4],
        'add_options_page' => [2, 4],
        'add_theme_page' => [2, 4],
        'add_plugins_page' => [2, 4],
        'add_users_page' => [2, 4],
        'add_dashboard_page' => [2, 4],
        'add_posts_page' => [2, 4],
        'add_media_page' => [2, 4],
        'add_links_page' => [2, 4],
        'add_pages_page' => [2, 4],
        'add_comments_page' => [2, 4],
    ];

    /** The table being built by {@see accept()}, until {@see finish()} hands it over. */
    private ?AdminPageTable $building = null;

    public function __construct(
        private readonly CallableResolver $callables,
        private readonly ReceiverResolver $receivers,
        private readonly ValueResolver $values,
    ) {
    }

    /**
     * Record one function's page registrations. The scan feeds every function
     * to this collector in the same sweep as the hook graph and REST routes.
     */
    public function accept(FunctionContext $context): void
    {
        $table = $this->building ??= new AdminPageTable();
        $types = new ClassTypeMap();

        foreach (BlockOrder::of($context->func->cfg) as $block) {
            foreach ($block->children as $op) {
                if (! $op instanceof Op\Expr\FuncCall && ! $op instanceof Op\Expr\NsFuncCall) {
                    continue;
                }

                $spec = self::registrar($op);

                if ($spec === null) {
                    continue;
                }

                $arguments = array_values(array_filter(
                    $op->args,
                    static fn (mixed $argument): bool => $argument instanceof Operand,
                ));

                $callback = $arguments[$spec[1]] ?? null;
                $capability = $arguments[$spec[0]] ?? null;

                if ($callback === null || $capability === null) {
                    continue;
                }

                $capabilities = $this->values->strings($capability);

                foreach ($this->callables->resolve($callback, [], $context, $types, $this->receivers) as $target) {
                    if ($target->userFunctionKey !== null) {
                        $table->add($target->userFunctionKey, $capabilities);
                    }
                }
            }
        }
    }

    /**
     * The table every accepted function built, and a fresh start after it.
     */
    public function finish(): AdminPageTable
    {
        $table = $this->building ?? new AdminPageTable();
        $this->building = null;

        return $table;
    }

    /**
     * @return array{0: int, 1: int}|null
     */
    private static function registrar(Op\Expr\FuncCall|Op\Expr\NsFuncCall $op): ?array
    {
        $names = $op instanceof Op\Expr\NsFuncCall
            ? [OperandHelper::literalString($op->nsName), OperandHelper::literalString($op->name)]
            : [OperandHelper::literalString($op->name)];

        foreach ($names as $name) {
            $spec = $name === null ? null : (self::REGISTRARS[strtolower(ltrim($name, '\\'))] ?? null);

            if ($spec !== null) {
                return $spec;
            }
        }

        return null;
    }
}

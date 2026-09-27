<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * What `filter_var()` and its relatives prove, by the filter constant.
 *
 * `filter_var( $v, FILTER_VALIDATE_INT )` returns a number or false, and
 * `filter_var( $v )` returns `$v` as it was. One function, and what comes back
 * depends on the second argument, so the catalogue names the strategy and this
 * reads the constant.
 *
 * A filter proves what the characters it lets through can carry, the same
 * proof a guard gets. Only filters whose output PHP fixes are credited:
 *
 * - a number or a boolean, from `FILTER_VALIDATE_INT`, `_FLOAT` and `_BOOL`
 * - an alphabet, from `FILTER_VALIDATE_IP`, `_MAC`, `FILTER_SANITIZE_NUMBER_INT`,
 *   `_NUMBER_FLOAT`, `_ENCODED` and `_EMAIL`
 * - no quotes or angle brackets, from `FILTER_SANITIZE_SPECIAL_CHARS`,
 *   `_FULL_SPECIAL_CHARS` and the deprecated `_STRING`
 *
 * Everything else passes the value through. `FILTER_VALIDATE_EMAIL` accepts a
 * quote, `FILTER_VALIDATE_DOMAIN` checks only label lengths without
 * `FILTER_FLAG_HOSTNAME`, and `FILTER_VALIDATE_URL` accepts `javascript:`.
 * A filter written as a number, or not written at all, is `FILTER_DEFAULT`.
 */
final class FilterProof
{
    private const NUMBERS = [
        'FILTER_VALIDATE_INT',
        'FILTER_VALIDATE_FLOAT',
        'FILTER_VALIDATE_BOOLEAN',
        'FILTER_VALIDATE_BOOL',
    ];

    /**
     * The characters each filter's result can hold, as a class body.
     */
    private const ALPHABETS = [
        'FILTER_VALIDATE_IP' => '0-9a-fA-F:.',
        'FILTER_VALIDATE_MAC' => '0-9a-fA-F:.\-',
        'FILTER_SANITIZE_NUMBER_INT' => '0-9+\-',
        'FILTER_SANITIZE_NUMBER_FLOAT' => '0-9+\-.,eE',
        'FILTER_SANITIZE_ENCODED' => 'A-Za-z0-9._%\-',
        'FILTER_SANITIZE_EMAIL' => 'A-Za-z0-9!#$%&\'*+\-=?^_`{|}~@.\[\]',
    ];

    /**
     * The characters each filter encodes, so its result cannot hold them.
     */
    private const ENCODES = [
        'FILTER_SANITIZE_SPECIAL_CHARS' => '<>&"\'',
        'FILTER_SANITIZE_FULL_SPECIAL_CHARS' => '<>&"\'',
        'FILTER_SANITIZE_STRING' => '<>"\'',
        'FILTER_SANITIZE_STRIPPED' => '<>"\'',
    ];

    /**
     * The proof a filter gives, or null when it passes the value through.
     */
    public static function of(?string $filter): ?CharacterProof
    {
        $filter = strtoupper(ltrim($filter ?? 'FILTER_DEFAULT', '\\'));

        if (in_array($filter, self::NUMBERS, true)) {
            return CharacterProof::complete();
        }

        if (isset(self::ALPHABETS[$filter])) {
            $characters = CharacterProof::expandClass(self::ALPHABETS[$filter]);

            return $characters === null ? null : CharacterProof::ofCharacters($characters);
        }

        if (isset(self::ENCODES[$filter])) {
            return CharacterProof::ofAllExcept(self::ENCODES[$filter]);
        }

        return null;
    }

    /**
     * The name of the filter constant an argument holds. Null for a missing
     * argument; an empty string for one that is not a constant, which no
     * filter is named.
     */
    public static function nameOf(?Operand $argument): ?string
    {
        if ($argument === null) {
            return null;
        }

        $definition = OperandHelper::definingOp($argument);

        if (! $definition instanceof Op\Expr\ConstFetch) {
            return '';
        }

        $name = OperandHelper::literalString($definition->name);

        return $name === null ? '' : substr($name, (int) strrpos('\\' . $name, '\\'));
    }
}

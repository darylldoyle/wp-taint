<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use RuntimeException;

/**
 * A function's taint fixed point did not settle, in a debug run.
 *
 * Only thrown when `WP_TAINT_DEBUG` is set. A production scan degrades to a
 * warning and incomplete results for the one function; a debug run — which the
 * test suite is — treats it as the engine bug it is, and the message names the
 * operand two ops could not agree on. See {@see FunctionAnalysis}.
 */
final class NonConvergenceError extends RuntimeException
{
}

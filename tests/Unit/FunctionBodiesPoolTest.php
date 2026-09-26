<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Taint\FunctionBodies;
use Enshrined\WpTaint\Taint\UserFunctionTable;

/**
 * Three copies of one class, each in its own file, plus a filler file big
 * enough to fill the cache, so the copies can only ever be pooled.
 *
 * @return array{bodies: FunctionBodies, table: UserFunctionTable, copies: list<string>, directory: string}
 */
function pooledCopies(): array
{
    $directory = sys_get_temp_dir() . '/wp-taint-pool-' . bin2hex(random_bytes(6));
    $class = "<?php\nclass Acme_Bundled {\n"
        . "    public function m1( \$x ) { return \$x . '1'; }\n"
        . "    public function m2( \$x ) { return \$x . '2'; }\n"
        . "    public function m3( \$x ) { return \$x . '3'; }\n"
        . "}\n";
    $copies = [];

    foreach (['a', 'b', 'c'] as $copy) {
        mkdir($directory . '/' . $copy, 0o755, true);
        file_put_contents($directory . '/' . $copy . '/dup.php', $class);
        $copies[] = $directory . '/' . $copy . '/dup.php';
    }

    // The pool is an eighth of the budget: room for the three copies. The
    // cache is the rest, and the filler takes it all.
    $copySize = strlen($class) * 60;
    $budget = 8 * (3 * $copySize + 1);
    $cache = $budget - intdiv($budget, 8);
    $filler = $directory . '/filler.php';
    $fillerSource = "<?php\n";
    file_put_contents($filler, $fillerSource . str_repeat('/', max(0, intdiv($cache, 60) - strlen($fillerSource))));

    $builder = new CfgBuilder($directory);
    $bodies = new FunctionBodies($builder, $budget);
    $table = new UserFunctionTable();

    $fillerFile = $builder->buildFromFile($filler)->file();
    $fillerFile->releaseAst();
    $bodies->add($fillerFile);

    foreach ($copies as $path) {
        $file = $builder->buildFromFile($path)->file();
        $table->addFile($file);
    }

    return ['bodies' => $bodies, 'table' => $table, 'copies' => $copies, 'directory' => $directory];
}

/**
 * Every body of every method, in the order the resolver asks for them: all
 * the copies of m1, then of m2, then of m3.
 *
 * @param array{bodies: FunctionBodies, table: UserFunctionTable, copies: list<string>, directory: string} $setup
 */
function fetchInResolverOrder(array $setup): void
{
    foreach (['m1', 'm2', 'm3'] as $method) {
        foreach ($setup['table']->all() as $meta) {
            if ($meta->name === $method) {
                $setup['bodies']->context($meta);
            }
        }
    }
}

function removeDirectory(string $directory): void
{
    foreach (
        new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        ) as $entry
    ) {
        $entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
    }

    rmdir($directory);
}

it('rebuilds each copy once while one owner file is served', function (): void {
    $setup = pooledCopies();

    try {
        $setup['bodies']->retainFor($setup['copies'][0]);
        fetchInResolverOrder($setup);

        expect($setup['bodies']->rebuilds())->toBe(3);
        expect($setup['bodies']->pooled())->toBeGreaterThan(0);
    } finally {
        removeDirectory($setup['directory']);
    }
});

it('rebuilds every copy for every method with no owner, as before the pool', function (): void {
    $setup = pooledCopies();

    try {
        fetchInResolverOrder($setup);

        expect($setup['bodies']->rebuilds())->toBe(9);
        expect($setup['bodies']->pooled())->toBe(0);
    } finally {
        removeDirectory($setup['directory']);
    }
});

it('empties the pool when the owner changes', function (): void {
    $setup = pooledCopies();

    try {
        $setup['bodies']->retainFor($setup['copies'][0]);
        fetchInResolverOrder($setup);
        $setup['bodies']->retainFor($setup['copies'][1]);

        expect($setup['bodies']->pooled())->toBe(0);

        fetchInResolverOrder($setup);

        expect($setup['bodies']->rebuilds())->toBe(6);
    } finally {
        removeDirectory($setup['directory']);
    }
});

it('never pools with a budget of zero, which rebuilds on every request', function (): void {
    $bodies = new FunctionBodies(new CfgBuilder(sys_get_temp_dir()), 0);

    expect($bodies->poolBudget())->toBe(0);
    expect((new FunctionBodies(null, null))->poolBudget())->toBe(0);
    expect((new FunctionBodies(null, 8 * 1024))->poolBudget())->toBe(1024);
});

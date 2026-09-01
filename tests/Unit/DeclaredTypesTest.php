<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Taint\DeclaredTypes;
use Enshrined\WpTaint\Taint\UserFunctionTable;

function declaredTypesFor(string $code): DeclaredTypes
{
    $result = (new CfgBuilder('/tmp'))->build($code, '/tmp/declared-types-snippet.php');
    $table = new UserFunctionTable();
    $table->addFile($result->file());

    return $table->declaredTypes();
}

it('finds a typed property declared on the parent through the subclass', function (): void {
    $declared = declaredTypesFor(<<<'PHP'
        <?php
        class Acme_DB {}
        class Base { protected Acme_DB $db; }
        class Child extends Base {}
        PHP);

    expect($declared->propertyClassOf('Child', 'db'))->toBe('Acme_DB');
    expect($declared->propertyClassOf('Base', 'db'))->toBe('Acme_DB');
});

it('finds a typed property brought in by a trait', function (): void {
    $declared = declaredTypesFor(<<<'PHP'
        <?php
        class Acme_DB {}
        trait Has_DB { protected Acme_DB $db; }
        class Uses { use Has_DB; }
        PHP);

    expect($declared->propertyClassOf('Uses', 'db'))->toBe('Acme_DB');
});

it('resolves a self-typed property to the declaring class', function (): void {
    $declared = declaredTypesFor(<<<'PHP'
        <?php
        class Acme_Node { private ?self $inner = null; }
        PHP);

    expect($declared->propertyClassOf('Acme_Node', 'inner'))->toBe('Acme_Node');
});

it('resolves a parent-typed property one level up', function (): void {
    $declared = declaredTypesFor(<<<'PHP'
        <?php
        class Acme_Base {}
        class Acme_Child extends Acme_Base { private ?parent $up = null; }
        PHP);

    // php-cfg's name resolver rewrites a `parent` type hint to the class name
    // before this index sees it; the resolveOwnReference branch is the safety
    // net for the spellings it does not rewrite, such as `new parent()`.
    expect($declared->propertyClassOf('Acme_Child', 'up'))->toBe('Acme_Base');
});

it('resolves `new self()` written to a property', function (): void {
    $declared = declaredTypesFor(<<<'PHP'
        <?php
        class Acme_Chain {
            private $next;
            public function __construct() { $this->next = new self(); }
        }
        PHP);

    expect($declared->propertyClassOf('Acme_Chain', 'next'))->toBe('Acme_Chain');
});

it('still refuses a property seen holding two different classes', function (): void {
    $declared = declaredTypesFor(<<<'PHP'
        <?php
        class A {}
        class B {}
        class Holder {
            private $thing;
            public function __construct() { $this->thing = new A(); }
            public function swap() { $this->thing = new B(); }
        }
        PHP);

    expect($declared->propertyClassOf('Holder', 'thing'))->toBeNull();
});

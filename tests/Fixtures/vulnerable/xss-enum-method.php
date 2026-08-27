<?php

/**
 * Taint reaching output from inside an enum method.
 *
 * php-cfg has no idea what an enum is; CompatibilityVisitor rewrites it to a
 * final class with the cases as constants, which keeps the method bodies
 * analysable.
 */

enum AcmeView: string
{
    case ListView = 'list';
    case GridView = 'grid';

    public function heading(): string
    {
        return '<h1>' . $_GET['heading'] . '</h1>';
    }

    public function render(): void
    {
        echo $this->heading(); // wp-taint-expect wp.xss.unescaped-output html
    }
}

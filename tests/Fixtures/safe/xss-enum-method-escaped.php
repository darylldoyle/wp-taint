<?php

/**
 * The same enum method with escaping applied.
 */

enum AcmeView: string
{
    case ListView = 'list';
    case GridView = 'grid';

    public function heading(): string
    {
        return '<h1>' . esc_html($_GET['heading']) . '</h1>';
    }

    public function render(): void
    {
        echo $this->heading();
    }
}

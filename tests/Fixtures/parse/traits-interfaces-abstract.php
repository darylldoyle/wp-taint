<?php

interface Renderable
{
    public function render(): string;
}

trait HasLabel
{
    protected string $label = '';

    public function label(): string
    {
        return $this->label;
    }
}

trait HasSlug
{
    public function slug(): string
    {
        return 'slug';
    }
}

abstract class Base implements Renderable
{
    use HasLabel;
    use HasSlug {
        slug as protected baseSlug;
    }

    abstract public function render(): string;

    final public function wrapped(): string
    {
        return '<div>' . $this->render() . '</div>';
    }
}

final class Concrete extends Base
{
    public function render(): string
    {
        return $this->label() . $this->baseSlug();
    }
}

$anon = new class extends Base {
    public function render(): string
    {
        return 'anon';
    }
};

echo (new Concrete())->wrapped(), $anon->wrapped();

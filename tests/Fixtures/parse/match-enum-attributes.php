<?php

#[Attribute(Attribute::TARGET_CLASS)]
final class Marker
{
    public function __construct(public readonly string $label = '')
    {
    }
}

enum Status: string
{
    case Draft = 'draft';
    case Live = 'live';

    public function label(): string
    {
        return match ($this) {
            self::Draft => 'Draft',
            self::Live => 'Live',
        };
    }
}

enum Pure
{
    case One;
    case Two;
}

#[Marker('demo')]
final class Widget
{
    public function __construct(
        private readonly Status $status = Status::Draft,
        protected int|string $id = 0,
        public ?Pure $pure = null,
    ) {
    }

    public function describe(): string
    {
        return match (true) {
            $this->id === 0 => 'unsaved',
            default => $this->status->label(),
        };
    }
}

$status = Status::Live;
echo $status->label();

$widget = new Widget(Status::Draft, 7);
echo $widget->describe();

<?php

namespace DreamFactory\Core\AAuth\Protocol;

/** An RFC 8941 Token bare item (distinct from a String). */
final class SfToken implements \Stringable
{
    public function __construct(public readonly string $value)
    {
    }

    public function __toString(): string
    {
        return $this->value;
    }
}

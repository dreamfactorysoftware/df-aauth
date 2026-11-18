<?php

namespace DreamFactory\Core\AAuth\Protocol;

/** An RFC 8941 Byte Sequence bare item; $bin holds the decoded bytes. */
final class SfBytes
{
    public function __construct(public readonly string $bin)
    {
    }
}

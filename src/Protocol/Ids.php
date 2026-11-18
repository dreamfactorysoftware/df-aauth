<?php

namespace DreamFactory\Core\AAuth\Protocol;

final class Ids
{
    /** CSPRNG id, base64url without padding (16 bytes => 22 chars). */
    public static function random(int $bytes = 16): string
    {
        return B64::url(random_bytes(max(1, $bytes)));
    }
}

<?php

namespace DreamFactory\Core\AAuth\Protocol;

/**
 * Finds the issuer key for a JWT: (iss, dwk, kid) => ['jwk' => public JWK, 'meta' => issuer metadata array].
 * Throws AAuthError (Signature-Error codes unknown_key, issuer_missing, issuer_mismatch, invalid_key, ...).
 */
interface KeyResolver
{
    public function resolve(string $iss, string $dwk, ?string $kid): array;
}

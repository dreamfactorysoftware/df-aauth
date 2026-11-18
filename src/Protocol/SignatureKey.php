<?php

namespace DreamFactory\Core\AAuth\Protocol;

/**
 * Signature-Key header (signature-key-09 §3): an SF Dictionary keyed by signature label.
 * AAuth agents MUST use the `jwt` scheme: `sig=jwt;jwt="<compact JWT>"`.
 */
final class SignatureKey
{
    public const SCHEMES = ['hwk', 'jkt-jwt', 'jwks_uri', 'jwks', 'jwt', 'self-jwt', 'x509', 'cached'];

    /**
     * Parse and select one member: label "sig" if present, else the only member.
     * Returns ['label' => 'sig', 'scheme' => 'jwt', 'jwt' => '...', 'params' => [all params, plain]].
     *
     * Errors (401 + Signature-Error): malformed header / no selectable member => invalid_signature;
     * scheme other than jwt (incl. registered hwk, jwks_uri, x509, ...) => unsupported_scheme
     * (+ Accept-Signature-Scheme: jwt); jwt parameter missing or not a String => invalid_key.
     * $label: select this label instead of the default rule.
     */
    public static function parse(string $header, ?string $label = null): array
    {
        try {
            $dict = StructuredFields::parseDictionary($header);
        } catch (\InvalidArgumentException $e) {
            throw AAuthError::signature('invalid_signature', 'Malformed Signature-Key header');
        }
        if ($label === null) {
            $label = isset($dict['sig']) ? 'sig' : (count($dict) === 1 ? (string) array_key_first($dict) : null);
        }
        if ($label === null || !isset($dict[$label])) {
            throw AAuthError::signature('invalid_signature', 'Signature-Key has no usable member (expected label "sig")');
        }
        $m = $dict[$label];
        if (isset($m['items']) || !($m['value'] instanceof SfToken)) {
            throw AAuthError::signature('invalid_signature', 'Signature-Key scheme must be a token');
        }
        $scheme = $m['value']->value;
        if ($scheme !== 'jwt') {
            throw AAuthError::signature('unsupported_scheme', "Signature-Key scheme \"{$scheme}\" is not supported; use jwt");
        }
        $jwt = $m['params']['jwt'] ?? null;
        if (!is_string($jwt) || $jwt === '') {
            throw AAuthError::signature('invalid_key', 'Signature-Key jwt parameter missing or not a string');
        }
        return [
            'label' => $label,
            'scheme' => $scheme,
            'jwt' => $jwt,
            'params' => array_map([StructuredFields::class, 'plain'], $m['params']),
        ];
    }

    /** Strict interop wire form: `<label>=jwt;jwt="<jwt>"` (no extra params). */
    public static function jwt(string $label, string $jwt): string
    {
        return StructuredFields::serializeKey($label) . '=jwt;jwt=' . StructuredFields::serializeString($jwt);
    }
}

<?php

namespace DreamFactory\Core\AAuth\Protocol;

/**
 * RFC 9421 HTTP Message Signatures, AAuth profile (§11.3, signature-key-09).
 *
 * Wire form emitted (strict interop form accepted by the reference demo):
 *   Signature-Key:   sig=jwt;jwt="<token>"
 *   Signature-Input: sig=("@method" "@authority" "@path" "signature-key"[ "content-type" "content-digest"][ extra...]);created=<now>
 *   Signature:       sig=:<standard base64 of the raw signature>:
 *   Content-Digest:  sha-256=:<standard base64>:
 * No alg, no keyid.
 */
final class HttpSignature
{
    public const BASE = ['@method', '@authority', '@path', 'signature-key'];
    public const BODY = ['content-type', 'content-digest'];
    public const LABEL = 'sig';

    /**
     * Returns the headers to add (canonical names): Signature-Key, Signature-Input, Signature, plus
     * Content-Type (the caller's value from $headers, default application/json) and Content-Digest when
     * $body !== ''. $extra lists further components to cover (e.g. ['@query'], which covers "?" when the
     * URL has no query). Header components in $extra are read from $headers.
     */
    public static function sign(string $method, string $url, string $sigKeyJwt, array $privateJwk, array $headers = [], string $body = '', array $extra = [], ?int $now = null): array
    {
        $u = parse_url($url);
        if ($u === false || !isset($u['host'])) {
            throw new \InvalidArgumentException('sign() needs an absolute URL');
        }
        $h = [];
        foreach ($headers as $k => $v) {
            $h[strtolower((string) $k)] = (string) $v;
        }
        $out = [];
        $components = self::BASE;
        if ($body !== '') {
            $h['content-type'] ??= 'application/json';
            $h['content-digest'] = ContentDigest::sha256($body);
            $out['Content-Type'] = $h['content-type'];
            $out['Content-Digest'] = $h['content-digest'];
            array_push($components, ...self::BODY);
        }
        foreach ($extra as $c) {
            $c = strtolower((string) $c);
            if (!in_array($c, $components, true)) {
                $components[] = $c;
            }
        }
        $sigKey = SignatureKey::jwt(self::LABEL, $sigKeyJwt);
        $h['signature-key'] = $sigKey;
        $out['Signature-Key'] = $sigKey;

        $params = StructuredFields::serializeInnerList($components, ['created' => $now ?? time()]);
        $parts = new HttpRequestParts($method, self::authorityOf($u), $u['path'] ?? '', $u['query'] ?? null, $h, $body);
        $sig = Jws::sign(self::base($components, $params, $parts), $privateJwk);

        $out['Signature-Input'] = self::LABEL . '=' . $params;
        $out['Signature'] = self::LABEL . '=:' . base64_encode($sig) . ':';
        return $out;
    }

    /**
     * Verify the request signature with $publicJwk (the token's cnf.jwk, verified by the caller).
     *
     * Checks, in order: Signature/Signature-Input/Signature-Key present; Signature-Key member (label "sig" or the
     * only member, jwt scheme); Signature-Input member for that label; required components (BASE, content-type
     * and content-digest when the body is non-empty, @query when $requireQuery and the query is non-empty,
     * $requiredExtra); created (older than $window => invalid_signature, ahead by more than $window => clock_skew);
     * expires; Content-Digest against the body; the signature itself.
     *
     * The RFC 9421 `alg` parameter is ignored, as -11 §11.3.3.2 requires ("verifiers MUST ignore it");
     * pass $rejectAlgParam = true to reject it instead (the reference demo's behaviour).
     *
     * Returns ['label', 'components', 'created', 'expires' (?int), 'params' (plain), 'signature' (raw bytes), 'base'].
     */
    public static function verify(HttpRequestParts $req, array $publicJwk, int $now, int $window = 60, bool $requireQuery = false, array $requiredExtra = [], bool $rejectAlgParam = false): array
    {
        $sk = $req->header('signature-key');
        $si = $req->header('signature-input');
        $sg = $req->header('signature');
        if ($sk === null || $si === null || $sg === null || trim($sk) === '' || trim($si) === '' || trim($sg) === '') {
            throw AAuthError::signature('invalid_signature', 'Signature, Signature-Input and Signature-Key are all required');
        }
        $label = SignatureKey::parse($sk)['label'];

        try {
            $inputs = StructuredFields::parseDictionary($si);
        } catch (\InvalidArgumentException) {
            throw AAuthError::signature('invalid_signature', 'Malformed Signature-Input');
        }
        $member = $inputs[$label] ?? null;
        if (!is_array($member) || !isset($member['items'])) {
            throw AAuthError::signature('invalid_signature', "Signature-Input has no inner list for label \"{$label}\"");
        }
        $components = [];
        foreach ($member['items'] as $it) {
            if (!is_string($it['value'])) {
                throw AAuthError::signature('invalid_signature', 'Covered components must be strings');
            }
            if ($it['params'] !== []) {
                throw AAuthError::signature('invalid_signature', "Component parameters are not supported ({$it['value']})");
            }
            if (in_array($it['value'], $components, true)) {
                throw AAuthError::signature('invalid_signature', "Component {$it['value']} is covered twice");
            }
            $components[] = $it['value'];
        }
        $params = $member['params'];
        if ($rejectAlgParam && array_key_exists('alg', $params)) {
            throw AAuthError::signature('invalid_signature', 'The alg signature parameter must not be sent');
        }

        $required = self::BASE;
        if ($req->body !== '') {
            array_push($required, ...self::BODY);
        }
        if ($requireQuery && $req->query !== null && $req->query !== '') {
            $required[] = '@query';
        }
        foreach ($requiredExtra as $c) {
            $c = strtolower((string) $c);
            if (!in_array($c, $required, true)) {
                $required[] = $c;
            }
        }
        $missing = array_values(array_diff($required, $components));
        if ($missing !== []) {
            throw AAuthError::invalidInput($required, 'Signature must also cover: ' . implode(', ', $missing));
        }

        $created = $params['created'] ?? null;
        if (!is_int($created)) {
            throw AAuthError::signature('invalid_signature', 'Signature-Input must include an integer created');
        }
        if ($now - $created > $window) {
            throw AAuthError::signature('invalid_signature', "Signature created more than {$window}s ago");
        }
        if ($created - $now > $window) {
            throw AAuthError::signature('clock_skew', "Signature created more than {$window}s in the future");
        }
        $expires = $params['expires'] ?? null;
        if ($expires !== null) {
            if (!is_int($expires)) {
                throw AAuthError::signature('invalid_signature', 'expires must be an integer');
            }
            if ($expires < $now) {
                throw AAuthError::signature('invalid_signature', 'Signature has expired');
            }
        }

        if ($req->body !== '' || in_array('content-digest', $components, true)) {
            $cd = $req->header('content-digest');
            if ($cd === null || !ContentDigest::verify($cd, $req->body)) {
                throw AAuthError::signature('invalid_signature', 'Content-Digest does not match the body');
            }
        }

        try {
            $sigDict = StructuredFields::parseDictionary($sg);
        } catch (\InvalidArgumentException) {
            throw AAuthError::signature('invalid_signature', 'Malformed Signature header');
        }
        $sigVal = $sigDict[$label]['value'] ?? null;
        if (!$sigVal instanceof SfBytes || isset($sigDict[$label]['items'])) {
            throw AAuthError::signature('invalid_signature', "Signature has no byte sequence for label \"{$label}\"");
        }

        Jwk::assertSupportedPublic($publicJwk);
        $serialized = StructuredFields::serializeInnerList($member['items'], $params);
        $base = self::base($components, $serialized, $req);
        if (!Jws::verify($base, $sigVal->bin, $publicJwk)) {
            throw AAuthError::signature('invalid_signature', 'HTTP message signature is invalid');
        }

        return [
            'label' => $label,
            'components' => $components,
            'created' => $created,
            'expires' => $expires,
            'params' => array_map([StructuredFields::class, 'plain'], $params),
            'signature' => $sigVal->bin,
            'base' => $base,
        ];
    }

    /**
     * RFC 9421 §2.5 signature base. $paramsSerialized is the serialized inner list with parameters
     * (the Signature-Input member value). Derived components: @method, @authority, @path, @query,
     * @request-target. A missing header component => invalid_signature.
     */
    public static function base(array $components, string $paramsSerialized, HttpRequestParts $req): string
    {
        $lines = [];
        foreach ($components as $c) {
            $lines[] = StructuredFields::serializeString($c) . ': ' . self::componentValue($c, $req);
        }
        $lines[] = '"@signature-params": ' . $paramsSerialized;
        return implode("\n", $lines);
    }

    /** RFC 9421 @authority from a parse_url() result: lowercase host, plus :port when not the scheme default. */
    public static function authorityOf(array $u): string
    {
        $a = strtolower($u['host'] ?? '');
        if (isset($u['port'])) {
            $default = ['https' => 443, 'http' => 80][strtolower($u['scheme'] ?? '')] ?? null;
            if ((int) $u['port'] !== $default) {
                $a .= ':' . $u['port'];
            }
        }
        return $a;
    }

    private static function componentValue(string $c, HttpRequestParts $req): string
    {
        switch ($c) {
            case '@method':
                return strtoupper($req->method);
            case '@authority':
                return strtolower($req->authority);
            case '@path':
                return $req->path === '' ? '/' : $req->path;
            case '@query':
                return '?' . ($req->query ?? '');
            case '@request-target':
                return ($req->path === '' ? '/' : $req->path) . ($req->query !== null ? '?' . $req->query : '');
        }
        if ($c === '' || $c[0] === '@') {
            throw AAuthError::signature('invalid_signature', "Unsupported derived component {$c}");
        }
        if ($c !== strtolower($c)) {
            throw AAuthError::signature('invalid_signature', "Component names must be lowercase ({$c})");
        }
        $v = $req->header($c);
        if ($v === null) {
            throw AAuthError::signature('invalid_signature', "Covered component {$c} is missing from the request");
        }
        return trim($v, " \t");
    }
}

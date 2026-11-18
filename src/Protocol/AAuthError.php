<?php

namespace DreamFactory\Core\AAuth\Protocol;

/**
 * An AAuth protocol failure that maps directly onto an HTTP response.
 *
 *  - $status  HTTP status
 *  - $error   spec error code (problem+json "error" member; Signature-Error code for 401 signature failures)
 *  - $detail  human-readable text
 *  - $headers extra response headers (name => value), e.g. Signature-Error, Accept-Signature-Alg
 */
final class AAuthError extends \RuntimeException
{
    public const ACCEPT_SIGNATURE_ALG = 'Ed25519, ES256';

    public function __construct(
        public int $status,
        public string $error,
        public string $detail = '',
        public array $headers = [],
    ) {
        parent::__construct($detail !== '' ? $detail : $error, $status);
    }

    /**
     * 401 with `Signature-Error: error=<code>` (AAuth uses 401 for every signature failure).
     * Adds `Accept-Signature-Alg` for unsupported_algorithm and `Accept-Signature-Scheme: jwt` for
     * unsupported_scheme automatically.
     */
    public static function signature(string $code, string $detail, array $extraHeaders = []): self
    {
        $headers = ['Signature-Error' => 'error=' . $code];
        if ($code === 'unsupported_algorithm') {
            $headers['Accept-Signature-Alg'] = self::ACCEPT_SIGNATURE_ALG;
        } elseif ($code === 'unsupported_scheme') {
            $headers['Accept-Signature-Scheme'] = 'jwt';
        }
        return new self(401, $code, $detail, array_merge($headers, $extraHeaders));
    }

    /** 401 `Signature-Error: error=invalid_input, required_input=("@method" ...)`. */
    public static function invalidInput(array $requiredComponents, string $detail): self
    {
        $list = '(' . implode(' ', array_map([StructuredFields::class, 'serializeString'], array_values($requiredComponents))) . ')';
        return new self(401, 'invalid_input', $detail, [
            'Signature-Error' => 'error=invalid_input, required_input=' . $list,
        ]);
    }

    public function isSignatureError(): bool
    {
        return isset($this->headers['Signature-Error']);
    }

    /**
     * Problem details body. Signature failures also carry the SK§5.2 `type` URN
     * (`urn:ietf:params:sig-error:<code>`); receivers act on `error`.
     */
    public function toProblem(): array
    {
        $p = ['error' => $this->error, 'detail' => $this->detail];
        if ($this->isSignatureError()) {
            $p = ['type' => 'urn:ietf:params:sig-error:' . $this->error] + $p;
        }
        return $p;
    }
}

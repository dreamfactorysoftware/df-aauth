<?php

namespace DreamFactory\Core\AAuth\Support;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use Illuminate\Http\JsonResponse;

/** application/problem+json responses ({error, detail}; signature errors also carry the SK§5.2 type). */
final class Problem
{
    /** Retry-After (seconds) on 503 temporarily_unavailable. */
    public const RETRY_AFTER = 30;

    /** 503 temporarily_unavailable + Retry-After: a check could not be made, so the request is refused. */
    public static function unavailable(string $detail = 'Try again shortly.'): JsonResponse
    {
        return self::fromError(self::unavailableError($detail));
    }

    public static function unavailableError(string $detail = 'Try again shortly.'): AAuthError
    {
        return new AAuthError(503, 'temporarily_unavailable', $detail, ['Retry-After' => (string)self::RETRY_AFTER]);
    }

    public static function response(int $status, string $error, string $detail = '', array $headers = []): JsonResponse
    {
        $body = ['error' => $error];
        if ($detail !== '') {
            $body['detail'] = $detail;
        }
        foreach ($headers as $name => $value) {
            if (strcasecmp($name, 'Signature-Error') === 0) {
                $body = ['type' => 'urn:ietf:params:sig-error:' . self::sigCode((string)$value)] + $body;
            }
        }
        $headers['Content-Type'] = 'application/problem+json';
        if (in_array($status, [401, 202], true)) {
            $headers['Cache-Control'] = 'no-store';
        }

        return new JsonResponse($body, $status, $headers, JSON_UNESCAPED_SLASHES);
    }

    public static function fromError(AAuthError $e): JsonResponse
    {
        return self::response($e->status, $e->error, $e->detail, $e->headers);
    }

    private static function sigCode(string $header): string
    {
        return preg_match('/error=([A-Za-z0-9_\-]+)/', $header, $m) ? $m[1] : 'invalid_signature';
    }
}

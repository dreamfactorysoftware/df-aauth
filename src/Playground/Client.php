<?php

namespace DreamFactory\Core\AAuth\Playground;

use DreamFactory\Core\AAuth\Protocol\HttpSignature;
use DreamFactory\Core\AAuth\Support\SafeHttp;

/**
 * Minimal HTTPS client for the Playground agent: real outbound requests, optionally signed with
 * the agent key and a token in Signature-Key. Records exactly what went over the wire.
 */
class Client
{
    public const MAX_BODY = 65536;

    /**
     * @return array{request: array, response: array}
     */
    public function send(string $method, string $url, ?string $body = null, ?string $jwt = null, ?array $privateJwk = null): array
    {
        $method = strtoupper($method);
        $body = $body ?? '';
        $headers = ['Accept' => 'application/json'];
        if ($body !== '') {
            $headers['Content-Type'] = 'application/json';
        }
        if ($jwt !== null && $privateJwk !== null) {
            $extra = parse_url($url, PHP_URL_QUERY) ? ['@query'] : [];
            $signed = HttpSignature::sign($method, $url, $jwt, $privateJwk, $headers, $body, $extra);
            foreach ($signed as $k => $v) {
                if (is_array($v) && count($v) === 2 && is_int($k)) {
                    [$k, $v] = $v;
                }
                $headers[$this->canon((string)$k)] = (string)$v;
            }
        }
        $wire = [];
        foreach ($headers as $k => $v) {
            $wire[] = "$k: $v";
        }
        $respHeaders = [];
        try {
            $tls = SafeHttp::tlsOptions(); // an issuer behind an internal CA (DF_AAUTH_CA_BUNDLE)
        } catch (\Throwable $e) {
            throw new \RuntimeException('DF_AAUTH_CA_BUNDLE is not a readable file or directory.');
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_HTTPHEADER => $wire,
            CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$respHeaders) {
                $len = strlen($line);
                $line = trim($line);
                if ($line === '' || stripos($line, 'HTTP/') === 0) {
                    if (stripos($line, 'HTTP/') === 0) {
                        $respHeaders = [];
                    }

                    return $len;
                }
                $pos = strpos($line, ':');
                if ($pos !== false) {
                    $respHeaders[] = [trim(substr($line, 0, $pos)), trim(substr($line, $pos + 1))];
                }

                return $len;
            },
        ] + $tls);
        if ($body !== '') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $out = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        unset($ch); // curl_close() is a no-op since PHP 8.0 and deprecated in 8.5
        if ($out === false) {
            throw new \RuntimeException("Request to $url failed: $err");
        }

        $reqHeaders = [];
        foreach ($headers as $k => $v) {
            $reqHeaders[] = [$k, $v];
        }

        return [
            'request' => ['method' => $method, 'url' => $url, 'headers' => $reqHeaders, 'body' => $body === '' ? null : $body],
            'response' => ['status' => $status, 'headers' => $respHeaders, 'body' => self::cut((string)$out)],
        ];
    }

    public static function header(array $headers, string $name): ?string
    {
        foreach ($headers as [$k, $v]) {
            if (strcasecmp($k, $name) === 0) {
                return $v;
            }
        }

        return null;
    }

    private static function cut(string $s): string
    {
        return strlen($s) > self::MAX_BODY ? substr($s, 0, self::MAX_BODY) . "\n…" : $s;
    }

    private function canon(string $name): string
    {
        return implode('-', array_map('ucfirst', explode('-', strtolower($name))));
    }
}

<?php

namespace DreamFactory\Core\AAuth\Http\Controllers;

use DreamFactory\Core\AAuth\Support\Cors;
use DreamFactory\Core\AAuth\Support\Keys;
use DreamFactory\Core\AAuth\Support\Metadata;
use DreamFactory\Core\AAuth\Support\Problem;
use DreamFactory\Core\AAuth\Support\Settings;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/** Public well-known documents and JWKS. 404 while AAuth is disabled. */
class MetadataController
{
    public function resource(Request $request): Response
    {
        return $this->doc($request, fn () => Metadata::resource());
    }

    public function person(Request $request): Response
    {
        return $this->doc($request, fn () => Settings::localPersonServerEnabled() ? Metadata::person() : null);
    }

    public function agent(Request $request): Response
    {
        return $this->doc($request, fn () => Metadata::agent());
    }

    public function jwks(Request $request, string $purpose): Response
    {
        return $this->doc($request, function () use ($purpose) {
            if (!in_array($purpose, Keys::PURPOSES, true) || ($purpose === 'person' && !Settings::localPersonServerEnabled())) {
                return null;
            }

            return Keys::jwks($purpose);
        });
    }

    private function doc(Request $request, \Closure $build): Response
    {
        if ($request->isMethod('OPTIONS')) {
            return Cors::preflight();
        }
        if (!Settings::enabled()) {
            return Cors::apply(Problem::response(404, 'not_found', 'Not found.'));
        }
        $doc = $build();
        if ($doc === null) {
            return Cors::apply(Problem::response(404, 'not_found', 'Not found.'));
        }

        return Cors::apply(new JsonResponse($doc, 200, ['Cache-Control' => 'public, max-age=60'], JSON_UNESCAPED_SLASHES));
    }

    /** Anything else under /aauth: 405 + Allow for a known path with the wrong method, else 404 (JSON). */
    public function fallback(Request $request, string $rest = ''): Response
    {
        $known = [
            'authorize' => 'POST, OPTIONS', 'person' => 'POST, OPTIONS', 'token' => 'POST, OPTIONS',
            'interact' => 'GET, POST', 'interact/next' => 'GET', 'interact/sso' => 'GET, POST', 'grants' => 'GET, POST', 'assets/interact.js' => 'GET',
        ];
        $allow = $known[$rest] ?? (preg_match('#^pending/[A-Za-z0-9_-]{8,32}$#', $rest) ? 'GET, DELETE, OPTIONS' : null);
        if ($allow !== null) {
            return Problem::response(405, 'method_not_allowed', 'Method not allowed.', ['Allow' => $allow]);
        }

        return Problem::response(404, 'not_found', 'Not found.');
    }
}

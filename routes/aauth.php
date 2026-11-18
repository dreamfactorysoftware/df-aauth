<?php

use DreamFactory\Core\AAuth\Http\Controllers\AuthorizeController;
use DreamFactory\Core\AAuth\Http\Controllers\MetadataController;
use DreamFactory\Core\AAuth\Http\Middleware\SecureSessionCookie;
use DreamFactory\Core\AAuth\PersonServer\GrantsController;
use DreamFactory\Core\AAuth\PersonServer\InteractController;
use DreamFactory\Core\AAuth\PersonServer\PsController;
use Illuminate\Support\Facades\Route;

/*
 * Loaded from ServiceProvider::register() via $app->booting(), i.e. BEFORE df-file's greedy
 * `{storage}/{path}` and df-core's `api/...` routes, which would otherwise swallow these paths.
 * None of these run in df.api. Every endpoint answers 404 while AAuth is disabled.
 */

// Public JSON: metadata, JWKS, resource authorization endpoint, person server token endpoints.
Route::match(['GET', 'OPTIONS'], '.well-known/aauth-resource.json', [MetadataController::class, 'resource']);
Route::match(['GET', 'OPTIONS'], '.well-known/aauth-person.json', [MetadataController::class, 'person']);
Route::match(['GET', 'OPTIONS'], '.well-known/aauth-agent.json', [MetadataController::class, 'agent']);
Route::match(['GET', 'OPTIONS'], 'aauth/jwks/{purpose}.json', [MetadataController::class, 'jwks'])->where('purpose', 'resource|person|agent');
Route::match(['POST', 'OPTIONS'], 'aauth/authorize', [AuthorizeController::class, 'authorize']);
Route::match(['POST', 'OPTIONS'], 'aauth/person', [PsController::class, 'person']);
Route::match(['POST', 'OPTIONS'], 'aauth/token', [PsController::class, 'token']);
Route::match(['GET', 'DELETE', 'OPTIONS'], 'aauth/pending/{id}', [PsController::class, 'poll'])->where('id', '[A-Za-z0-9_-]{8,32}');
Route::get('aauth/assets/interact.js', [InteractController::class, 'script']);

// Server-rendered consent pages (session + CSRF; Secure session cookie when the issuer is https;
// DF_AAUTH_SESSION_DRIVER for multi-node). /aauth/interact/sso is where single sign-on returns.
Route::middleware([SecureSessionCookie::class, 'web'])->group(function () {
    Route::get('aauth/interact', [InteractController::class, 'show']);
    Route::post('aauth/interact', [InteractController::class, 'submit']);
    Route::get('aauth/interact/next', [InteractController::class, 'next']);
    Route::get('aauth/interact/sso', [InteractController::class, 'ssoLanding']);
    Route::post('aauth/interact/sso', [InteractController::class, 'ssoComplete']);
    Route::get('aauth/grants', [GrantsController::class, 'show']);
    Route::post('aauth/grants', [GrantsController::class, 'submit']);
});

// Anything else under /aauth: a JSON problem (405 + Allow for a known path, else 404) instead of
// falling through to df-file's {storage}/{path} HTML 404.
Route::any('aauth/{rest}', [MetadataController::class, 'fallback'])->where('rest', '.*');

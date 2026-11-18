<?php

/*
 * df-aauth configuration. Every value is env-backed (config:cache safe). Policy (enabled, scopes,
 * trusted person servers, agents, grants) lives in the system database and is managed through
 * /api/v2/system/aauth.
 */
return [
    /* Public https origin of this DreamFactory (the AAuth server identifier). Falls back to the
       APP_URL origin when that is https. Never derived from the request Host. */
    'issuer' => env('DF_AAUTH_ISSUER'),
    /* Development only: allow http issuers and discovery of private/loopback addresses. */
    'allow_insecure' => (bool)env('DF_AAUTH_ALLOW_INSECURE', false),
    /* Agents, agent providers and person servers on internal networks. Discovery only fetches from
       public addresses unless admitted here (comma separated):
         DF_AAUTH_PRIVATE_HOSTS     hostnames, exact or "*.corp.internal" (subdomains); they may
                                    resolve to private-use addresses (10/8, 172.16/12, 192.168/16,
                                    100.64/10, fc00::/7), not loopback
         DF_AAUTH_PRIVATE_NETWORKS  CIDRs or addresses (10.20.0.0/16, 127.0.0.1); any host resolving
                                    inside them is admitted
       Link-local and cloud metadata addresses (169.254.0.0/16, fe80::/10, fd00:ec2::/32,
       100.100.100.200) are refused whatever is listed. */
    'private_hosts' => env('DF_AAUTH_PRIVATE_HOSTS', ''),
    'private_networks' => env('DF_AAUTH_PRIVATE_NETWORKS', ''),
    /* PEM CA bundle file (or c_rehash'd directory) that discovery and the Playground trust instead
       of the system store, for an internal CA. To keep trusting public CAs too, append your CA to a
       copy of the system bundle. Unreadable = every fetch fails (closed). */
    'ca_bundle' => env('DF_AAUTH_CA_BUNDLE'),
    /* Cache store (config/cache.php) for replay records, limits, code claims and discovery results;
       empty = the default store. With several DreamFactory nodes it must be shared (redis). */
    'cache_store' => env('DF_AAUTH_CACHE_STORE'),
    /* Session driver for the consent and grants pages only (they carry the signed-in person and the
       CSRF token between requests); empty = SESSION_DRIVER. With several nodes and no sticky
       sessions use redis, or database (table aauth_sessions, created by the df-aauth migrations). */
    'session_driver' => env('DF_AAUTH_SESSION_DRIVER'),
    /* Signing keys: retired keys stay published in the JWKS and accepted for this many seconds
       after a rotation (at least the longest token lifetime + 5 minutes). */
    'key_overlap' => (int)env('DF_AAUTH_KEY_OVERLAP', 86400),
    /* Rotate signing keys automatically once they are this many days old (php artisan schedule:run,
       which DreamFactory images run every minute). 0 = only by hand: php artisan df:aauth rotate-keys. */
    'key_rotation_days' => (int)env('DF_AAUTH_KEY_ROTATION_DAYS', 0),
    /* Consent sign-in through the DreamFactory login page (OAuth, OpenID Connect, SAML, LDAP...):
       auto = offered when an OAuth/OIDC/SAML login service is active, on, off. */
    'sso' => env('DF_AAUTH_SSO', 'auto'),
    /* The admin app's login route on the issuer origin (it returns to the consent page signed in). */
    'sso_login_path' => env('DF_AAUTH_SSO_LOGIN_PATH', '/dreamfactory/dist/#/auth/login'),
    'auth_token_ttl' => (int)env('DF_AAUTH_AUTH_TOKEN_TTL', 3600),
    'person_token_ttl' => (int)env('DF_AAUTH_PERSON_TOKEN_TTL', 3600),
    'resource_token_ttl' => (int)env('DF_AAUTH_RESOURCE_TOKEN_TTL', 300),
    'agent_token_ttl' => (int)env('DF_AAUTH_AGENT_TOKEN_TTL', 3600),
    'pending_ttl' => (int)env('DF_AAUTH_PENDING_TTL', 600),
    'signature_window' => (int)env('DF_AAUTH_SIGNATURE_WINDOW', 60),
    'activity_retention_days' => (int)env('DF_AAUTH_ACTIVITY_RETENTION_DAYS', 30),
    'fetch_timeout' => (int)env('DF_AAUTH_FETCH_TIMEOUT', 3),
    'fetch_max_bytes' => (int)env('DF_AAUTH_FETCH_MAX_BYTES', 262144),
    'discovery_cache_seconds' => (int)env('DF_AAUTH_DISCOVERY_CACHE_SECONDS', 300),
    /* Proxies whose X-Forwarded-For is believed for AAuth rate limits (comma separated IPs/CIDRs).
       Set it to the address your TLS proxy connects from; never to a range clients can reach. */
    'trusted_proxies' => env('DF_AAUTH_TRUSTED_PROXIES', ''),
    'playground_agent_name' => env('DF_AAUTH_PLAYGROUND_AGENT_NAME', 'DreamFactory Playground'),
];

<?php

namespace DreamFactory\Core\AAuth\PersonServer;

/**
 * How a person proves who they are on the consent and grants pages, beyond DreamFactory email +
 * password (SignIn). Bound in the container (DreamFactoryAccounts); tests bind a fake.
 */
interface Accounts
{
    /**
     * Active password-based directory services (LDAP, Active Directory) people sign in with, as
     * DreamFactory's login page lists them.
     *
     * @return array<int, array{name: string, label: string}>
     */
    public function directories(): array;

    /**
     * Checks a directory username + password the way DreamFactory's login does (bind, then the
     * service's shadow user and role mapping) without starting a DreamFactory session.
     * Returns the active DreamFactory user id, or null for wrong credentials / unknown service.
     */
    public function directoryLogin(string $service, string $username, string $password): ?int;

    /** True when a redirect-based login service (OAuth, OpenID Connect, SAML) is active. */
    public function hasSso(): bool;

    /**
     * Validates a DreamFactory session token (JWT: signature, expiry, blacklist, user) and returns
     * its active user id, or null.
     */
    public function sessionUser(string $jwt): ?int;
}

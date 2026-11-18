<?php

namespace DreamFactory\Core\AAuth\PersonServer;

use DreamFactory\Core\AAuth\Support\Users;

/**
 * Accounts backed by DreamFactory itself: the LDAP-group services (df-adldap: ldap, adldap) and
 * DreamFactory session tokens (tymon/jwt-auth, as df-core's AuthCheck verifies them).
 * Every DreamFactory dependency is resolved lazily and failures count as "no", so a DreamFactory
 * without df-adldap (or a broken directory) simply offers no directory sign-in.
 */
class DreamFactoryAccounts implements Accounts
{
    private const LDAP_GROUP = 'LDAP';   // DreamFactory\Core\Enums\ServiceTypeGroups::LDAP
    private const SSO_GROUPS = ['OAuth', 'SSO']; // ::OAUTH (OAuth, OpenID Connect), ::SSO (SAML)

    public function directories(): array
    {
        $out = [];
        try {
            $list = app('df.service')->getServiceListByGroup(self::LDAP_GROUP, ['name', 'type', 'label'], true);
        } catch (\Throwable $e) {
            return [];
        }
        foreach ((array)$list as $row) {
            $row = (array)$row;
            $name = trim((string)($row['name'] ?? ''));
            if ($name !== '') {
                $label = trim((string)($row['label'] ?? ''));
                $out[] = ['name' => $name, 'label' => $label !== '' ? $label : $name];
            }
        }

        return $out;
    }

    public function directoryLogin(string $service, string $username, string $password): ?int
    {
        if ($username === '' || $password === '') {
            return null; // an empty password would be an anonymous bind on many LDAP servers
        }
        $name = null;
        foreach ($this->directories() as $d) {
            if (strcasecmp($d['name'], $service) === 0) {
                $name = $d['name'];
            }
        }
        if ($name === null) {
            return null;
        }
        $svc = app('df.service')->getService($name);
        if (!is_object($svc) || !method_exists($svc, 'getDriver') || !method_exists($svc, 'createShadowADLdapUser')) {
            return null;
        }
        $driver = $svc->getDriver();
        if (!$driver->authenticate($username, $password)) {
            return null;
        }
        // DreamFactory's LDAP login (df-adldap LDAP::handleLogin) minus the session token: the
        // directory user becomes (or updates) its shadow DreamFactory user with the service's
        // default role and group -> role mapping, so consent sees the roles a DF login would.
        $user = $svc->createShadowADLdapUser($driver->getUser());
        $id = (int)(is_object($user) && method_exists($user, 'getKey') ? $user->getKey() : 0);
        $row = $id > 0 ? Users::find($id) : null;

        return $row && !empty($row['is_active']) ? $id : null;
    }

    public function hasSso(): bool
    {
        try {
            $sm = app('df.service');
            foreach (self::SSO_GROUPS as $group) {
                if (!empty($sm->getServiceListByGroup($group, ['name'], true))) {
                    return true;
                }
            }
        } catch (\Throwable $e) {
        }

        return false;
    }

    public function sessionUser(string $jwt): ?int
    {
        $jwt = trim($jwt);
        if ($jwt === '' || strlen($jwt) > 8192 || substr_count($jwt, '.') !== 2) {
            return null;
        }
        $facade = 'Tymon\\JWTAuth\\Facades\\JWTAuth';
        $utilities = 'DreamFactory\\Core\\Utility\\JWTUtilities';
        if (!class_exists($facade) || !class_exists($utilities)) {
            return null;
        }
        try {
            // signature (APP_KEY / JWT_SECRET), exp/nbf/iat and the logout blacklist
            $payload = $facade::setToken($jwt)->getPayload();
            // sub = md5(email) of an existing user, like every DreamFactory session check
            $utilities::verifyUser($payload);
            $id = (int)$payload->get('user_id');
        } catch (\Throwable $e) {
            return null;
        } finally {
            try {
                $facade::unsetToken();
            } catch (\Throwable $e) {
            }
        }
        $row = $id > 0 ? Users::find($id) : null;

        return $row && !empty($row['is_active']) ? $id : null;
    }
}

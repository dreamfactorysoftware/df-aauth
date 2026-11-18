#!/usr/bin/env node
// Agent Provider for the reference agent "Acme Reports" (the df-aauth demo deployment).
// Your own agent: `aauth init` + `aauth serve`, or createProviderHandler() from provider.mjs.
//
//   AAUTH_KEYS=/data/keys.json AAUTH_AGENT_ISSUER=https://agent.example PORT=8799 node server.mjs
//
// Serves:
//   /.well-known/aauth-agent.json   AP metadata (issuer, jwks_uri, name, callback_endpoint)
//   /jwks.json                      AP public key (signs agent tokens)
//   /callback                       where Person Servers send the browser after a decision
//   /                               what this is
//   /.well-known/aauth-person.json  a throwaway "untrusted" Person Server identity used only by
//   /test-ps/jwks.json              e2e scenarios 9 and 13 (it never issues tokens over HTTP)
import { loadOrCreateKeys, publicJwk, keysPath, DEFAULT_ISSUER } from './aauth.mjs';
import { startProvider } from './provider.mjs';

const ISSUER = String(process.env.AAUTH_AGENT_ISSUER || DEFAULT_ISSUER || '').replace(/\/+$/, '');
if (!ISSUER) {
  console.error('server.mjs: set AAUTH_AGENT_ISSUER to the https origin this Agent Provider is served from');
  process.exit(2);
}
const PORT = Number(process.env.PORT || 8799);
const HOST = process.env.HOST || '0.0.0.0';
const NAME = process.env.AAUTH_AGENT_NAME || 'Acme Reports';
const keys = loadOrCreateKeys(keysPath());

const routes = {};
if (keys.test_ps) {
  routes['/.well-known/aauth-person.json'] = {
    issuer: ISSUER,
    jwks_uri: `${ISSUER}/test-ps/jwks.json`,
    person_token_endpoint: `${ISSUER}/test-ps/person`,
    auth_token_endpoint: `${ISSUER}/test-ps/token`,
    name: 'Acme Test Person Server',
    scopes_supported: [],
    accept_signature_algs: ['Ed25519'],
  };
  routes['/test-ps/jwks.json'] = { keys: [publicJwk(keys.test_ps)] };
}

const server = await startProvider({ issuer: ISSUER, name: NAME, apKey: keys.ap, callback: true, routes, about: 'AAuth reference agent for DreamFactory.', port: PORT, host: HOST });
console.log(`${NAME} agent provider: ${ISSUER} (listening on ${HOST}:${PORT}, ap kid ${keys.ap.kid})`);
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => server.close(() => process.exit(0)));

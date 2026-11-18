#!/usr/bin/env bash
# df-aauth demo data, through the DreamFactory API only. Idempotent: re-run any time (for example
# after a container recreate, which loses the SQLite file but keeps the service row).
#
#   bin/demo-seed.sh <admin-password-file> [base-url] [user-password-file]
#     base-url            default http://127.0.0.1
#     user-password-file  default ./aauth-user-password (generated, mode 600)
#   ADMIN_EMAIL (default admin@example.com), USER_EMAIL (default jordan@example.com)
#
# Creates (only when missing):
#   - SQLite service `sales` ("Sales") with tables customers(id, name, email, city) and
#     orders(id, customer_id, total, status, created_at): 12 customers, 40 orders
#   - roles "Sales read" (sales _table/* GET, _schema/* GET) and
#     "Sales refunds" (sales _table/orders[/*] GET+PATCH, _table/customers[/*] GET)
#   - AAuth scopes sales.read and sales.refund on those roles (enabled)
#   - non-admin user "Jordan Lee" <$USER_EMAIL> with role "Sales read"
# It never touches other services or the admin account. Secrets are read from files and are never
# printed or put on a command line.
set -euo pipefail
ADMIN_PW_FILE="${1:?usage: demo-seed.sh <admin-password-file> [base-url] [user-password-file]}"
BASE="${2:-http://127.0.0.1}"
USER_PW_FILE="${3:-./aauth-user-password}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
USER_EMAIL="${USER_EMAIL:-jordan@example.com}"
[[ -r "$ADMIN_PW_FILE" ]] || { echo "[demo-seed] cannot read $ADMIN_PW_FILE" >&2; exit 1; }

exec python3 -I - "$BASE" "$ADMIN_EMAIL" "$ADMIN_PW_FILE" "$USER_PW_FILE" "$USER_EMAIL" <<'PY'
import json, os, secrets, string, sys, urllib.error, urllib.parse, urllib.request

base, admin_email, admin_pw_file, user_pw_file, user_email = sys.argv[1:6]
base = base.rstrip('/')

def say(msg):
    print(f"[demo-seed] {msg}", flush=True)

def http(method, path, body=None, token=None, form=None):
    headers = {'Accept': 'application/json'}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    elif body is not None:
        data = json.dumps(body).encode()
        headers['Content-Type'] = 'application/json'
    if token:
        headers['X-DreamFactory-Session-Token'] = token
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {'raw': raw.decode('utf-8', 'replace')[:300]}

def must(status_body, what):
    status, body = status_body
    if status >= 300:
        msg = body.get('error', {}).get('message') if isinstance(body.get('error'), dict) else body
        raise SystemExit(f"[demo-seed] {what} failed: HTTP {status}: {msg}")
    return body

def q(s):
    return urllib.parse.quote(s, safe='')

with open(admin_pw_file) as f:
    admin_pw = f.read().strip('\n')
tok = must(http('POST', '/api/v2/system/admin/session', form={'email': admin_email, 'password': admin_pw}), 'admin login')['session_token']

# 1. service
svc = must(http('GET', '/api/v2/system/service?filter=' + q("name='sales'"), token=tok), 'service lookup')['resource']
if svc:
    service_id = svc[0]['id']
    say(f"service sales exists (id {service_id})")
else:
    created = must(http('POST', '/api/v2/system/service', {'resource': [{
        'name': 'sales', 'label': 'Sales', 'description': 'AAuth demo data', 'type': 'sqlite',
        'is_active': True, 'config': {'database': 'sales.sqlite'}}]}, tok), 'create service')
    service_id = created['resource'][0]['id']
    say(f"service sales created (id {service_id})")

# 2. tables
tables = {t['name'] for t in must(http('GET', '/api/v2/sales/_schema', token=tok), 'schema list').get('resource', [])}
want = []
if 'customers' not in tables:
    want.append({'name': 'customers', 'label': 'Customers', 'field': [
        {'name': 'id', 'type': 'id'},
        {'name': 'name', 'type': 'string', 'size': 80, 'allow_null': False},
        {'name': 'email', 'type': 'string', 'size': 120},
        {'name': 'city', 'type': 'string', 'size': 60}]})
if 'orders' not in tables:
    want.append({'name': 'orders', 'label': 'Orders', 'field': [
        {'name': 'id', 'type': 'id'},
        {'name': 'customer_id', 'type': 'integer', 'allow_null': False},
        {'name': 'total', 'type': 'decimal', 'precision': 10, 'scale': 2},
        {'name': 'status', 'type': 'string', 'size': 20},
        {'name': 'created_at', 'type': 'datetime'}]})
if want:
    must(http('POST', '/api/v2/sales/_schema', {'resource': want}, tok), 'create tables')
    say('tables created: ' + ', '.join(t['name'] for t in want))
else:
    say('tables exist')

# 3. rows
customers = [
    ('Ava Patel', 'Austin'), ('Ben Okafor', 'Boston'), ('Chloe Martin', 'Chicago'), ('Diego Alvarez', 'Denver'),
    ('Emma Schultz', 'Seattle'), ('Farah Haddad', 'Portland'), ('George Kim', 'San Diego'), ('Hana Sato', 'San Jose'),
    ('Isaac Cohen', 'New York'), ('Julia Rossi', 'Miami'), ('Kofi Mensah', 'Atlanta'), ('Lena Novak', 'Phoenix')]
def count(table):
    body = must(http('GET', f'/api/v2/sales/_table/{table}?include_count=true&limit=1', token=tok), f'count {table}')
    return int(body.get('meta', {}).get('count', len(body.get('resource', []))))
if count('customers') == 0:
    rows = [{'name': n, 'email': n.split()[0].lower() + '@example.com', 'city': c} for n, c in customers]
    must(http('POST', '/api/v2/sales/_table/customers', {'resource': rows}, tok), 'insert customers')
    say(f'{len(rows)} customers inserted')
if count('orders') == 0:
    statuses = ['paid', 'paid', 'shipped', 'paid', 'refunded', 'shipped', 'pending', 'paid']
    rows = []
    for i in range(40):
        rows.append({'customer_id': (i * 7) % 12 + 1, 'total': round(19.5 + (i * 37) % 480 + (i % 4) * 0.25, 2),
                     'status': statuses[i % len(statuses)],
                     'created_at': f'2026-10-{(i % 28) + 1:02d} {9 + i % 9:02d}:{(i * 13) % 60:02d}:00'})
    must(http('POST', '/api/v2/sales/_table/orders', {'resource': rows}, tok), 'insert orders')
    say(f'{len(rows)} orders inserted')

# 4. roles
GET, PATCH = 1, 8
def ensure_role(name, description, access):
    found = must(http('GET', '/api/v2/system/role?filter=' + q(f"name='{name}'"), token=tok), 'role lookup')['resource']
    if found:
        say(f'role "{name}" exists (id {found[0]["id"]})')
        return found[0]['id']
    rsa = [{'service_id': service_id, 'component': c, 'verb_mask': m, 'requestor_mask': 1, 'filters': [], 'filter_op': 'AND'}
           for c, m in access]
    created = must(http('POST', '/api/v2/system/role', {'resource': [{
        'name': name, 'description': description, 'is_active': True, 'role_service_access_by_role_id': rsa}]}, tok), f'create role {name}')
    rid = created['resource'][0]['id']
    say(f'role "{name}" created (id {rid})')
    return rid
read_id = ensure_role('Sales read', 'Read customers and orders', [('_table/*', GET), ('_schema/*', GET)])
refund_id = ensure_role('Sales refunds', 'Update order status', [
    ('_table/orders', GET | PATCH), ('_table/orders/*', GET | PATCH), ('_table/customers', GET), ('_table/customers/*', GET)])

# 5. AAuth scopes
configured = {r['scope']: r for r in must(http('GET', '/api/v2/system/aauth/scopes', token=tok), 'scope list')['resource']}
for rid, scope, desc in [(read_id, 'sales.read', 'Read customers and orders'), (refund_id, 'sales.refund', 'Update order status')]:
    have = configured.get(scope)
    if have and have['role_id'] == rid and have.get('description') is not None:
        # configured earlier: leave the admin's description and enabled switch alone
        say(f"scope {scope} exists -> role {have['role_name']} (enabled={have['enabled']})")
        continue
    body = must(http('PATCH', f'/api/v2/system/aauth/scopes/{rid}', {'scope': scope, 'description': desc, 'enabled': True}, tok), f'scope {scope}')
    say(f"scope {body['scope']} -> role {body['role_name']} (enabled={body['enabled']})")

# 6. Jordan
apps = must(http('GET', '/api/v2/system/app?filter=' + q("name='aauth'"), token=tok), 'app lookup')['resource']
if not apps:
    apps = must(http('GET', '/api/v2/system/app?limit=1&order=id', token=tok), 'app list')['resource']
app_id = apps[0]['id']
new_pw = False
if os.path.exists(user_pw_file):
    with open(user_pw_file) as f:
        user_pw = f.read().strip('\n')
else:
    alphabet = string.ascii_letters + string.digits
    user_pw = ''.join(secrets.choice(alphabet) for _ in range(20))
    fd = os.open(user_pw_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(user_pw + '\n')
    new_pw = True
    say(f'generated a password for {user_email} in {user_pw_file}')
found = must(http('GET', '/api/v2/system/user?related=user_to_app_to_role_by_user_id&filter=' + q(f"email='{user_email}'"), token=tok), 'user lookup')['resource']
if not found:
    must(http('POST', '/api/v2/system/user', {'resource': [{
        'name': 'Jordan Lee', 'first_name': 'Jordan', 'last_name': 'Lee', 'email': user_email,
        'password': user_pw, 'is_active': True,
        'user_to_app_to_role_by_user_id': [{'app_id': app_id, 'role_id': read_id}]}]}, tok), 'create user')
    say('user Jordan Lee created with role "Sales read"')
else:
    u = found[0]
    patch = {}
    if new_pw:
        patch['password'] = user_pw
    if not any(int(r.get('role_id') or 0) == int(read_id) for r in u.get('user_to_app_to_role_by_user_id', [])):
        patch['user_to_app_to_role_by_user_id'] = [{'app_id': app_id, 'role_id': read_id}]
    if patch:
        must(http('PATCH', f'/api/v2/system/user/{u["id"]}', patch, tok), 'update user')
    say('user Jordan Lee exists' + (' (updated)' if patch else ''))
say('done')
PY

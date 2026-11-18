// The person's side of the AAuth consent flow, driven over plain HTTP (cookie jar, CSRF tokens,
// manual redirects). Relies only on the "Consent page contract" in README.md. For automated tests
// against TEST instances only: it signs in with a password.
//
//   import { Browser, personAct } from '@dreamfactory/aauth-agent/person';
//   node person.mjs approve <interaction-url> <code> --email <e> [--deny] [--always]
//     (password from $AAUTH_PERSON_PASSWORD; prints {"result", "trail"}; exit 0 when the page
//      ended the way it was asked to, 1 otherwise)
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { REFERENCE } from './aauth.mjs';

let vlog = () => {};
export const setLogger = (fn) => (vlog = fn);

/** Passwords from env, stdin (two lines) or the reference deployment's files (agent/reference.json). Never printed. */
export function credentials({ stdin = false } = {}) {
  const read = (f) => {
    try {
      return fs.readFileSync(f, 'utf8').trim();
    } catch {
      return undefined;
    }
  };
  let adminPassword = process.env.DF_ADMIN_PASSWORD;
  let userPassword = process.env.DF_USER_PASSWORD;
  if (stdin) {
    const lines = fs.readFileSync(0, 'utf8').split(/\r?\n/).filter((l) => l !== '');
    adminPassword = adminPassword || lines[0];
    userPassword = userPassword || lines[1];
  }
  if (!adminPassword && REFERENCE.admin_password_file) adminPassword = read(REFERENCE.admin_password_file);
  if (!userPassword && REFERENCE.user_password_file) userPassword = read(REFERENCE.user_password_file);
  return { adminPassword, userPassword };
}

// ---------------------------------------------------------------------------
// Browser (cookie jar, manual redirects) and HTML scanning
// ---------------------------------------------------------------------------
const decodeEntities = (s) =>
  String(s).replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos|#39);/gi, (m, e) => {
    const l = e.toLowerCase();
    if (l === 'amp') return '&';
    if (l === 'lt') return '<';
    if (l === 'gt') return '>';
    if (l === 'quot') return '"';
    if (l === 'apos' || l === '#39') return "'";
    if (l.startsWith('#x')) return String.fromCodePoint(parseInt(l.slice(2), 16));
    return String.fromCodePoint(parseInt(l.slice(1), 10));
  });

export function attrs(tag) {
  const out = {};
  const body = tag.replace(/^<\s*[\w-]+/, '').replace(/\/?>$/, '');
  const re = /([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+)))?/g;
  let m;
  while ((m = re.exec(body))) out[m[1].toLowerCase()] = decodeEntities(m[2] ?? m[3] ?? m[4] ?? '');
  return out;
}
const tags = (html, name) => [...html.matchAll(new RegExp(`<${name}\\b[^>]*>`, 'gi'))].map((m) => attrs(m[0]));

export function scan(html) {
  const stateTag = html.match(/<[^>]*\sdata-aauth-state\s*=\s*["']?([\w-]+)[^>]*>/i);
  const a = stateTag ? attrs(stateTag[0]) : {};
  const errM = html.match(/<([\w-]+)\b[^>]*\sdata-aauth-error\b[^>]*>([\s\S]*?)<\/\1>/i);
  const forms = [...html.matchAll(/<form\b[^>]*>[\s\S]*?<\/form>/gi)].map((m) => {
    const open = m[0].match(/^<form\b[^>]*>/i)[0];
    return {
      attrs: attrs(open),
      inputs: tags(m[0], 'input'),
      buttons: [...tags(m[0], 'button'), ...tags(m[0], 'input').filter((i) => (i.type || '').toLowerCase() === 'submit')],
    };
  });
  const scopes = [...html.matchAll(/<[^>]*\sdata-aauth-scope\s*=[^>]*>/gi)].map((m) => {
    const t = attrs(m[0]);
    return { scope: t['data-aauth-scope'], grantable: t['data-aauth-grantable'] !== '0' };
  });
  return {
    state: a['data-aauth-state'] || null,
    result: a['data-aauth-result'] || null,
    error: errM ? decodeEntities(errM[2].replace(/<[^>]+>/g, '').trim()) : null,
    forms,
    scopes,
  };
}

export class Browser {
  constructor(name) {
    this.name = name;
    this.jar = new Map();
  }
  cookie() {
    return [...this.jar].map(([k, v]) => `${k}=${v}`).join('; ');
  }
  absorb(res) {
    const list = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    for (const c of list) {
      const [pair, ...attrsList] = c.split(';');
      const i = pair.indexOf('=');
      const k = pair.slice(0, i).trim();
      const v = pair.slice(i + 1).trim();
      const expired = attrsList.some((x) => /^\s*max-age\s*=\s*(0|-)/i.test(x)) || attrsList.some((x) => /^\s*expires=/i.test(x) && Date.parse(x.split('=')[1]) < Date.now());
      if (expired || v === '' || v === 'deleted') this.jar.delete(k);
      else this.jar.set(k, v);
    }
  }
  async go(method, url, form) {
    let body;
    let m = method;
    for (let hop = 0; hop < 10; hop++) {
      const headers = { cookie: this.cookie(), accept: 'text/html' };
      if (form && m === 'POST') {
        headers['content-type'] = 'application/x-www-form-urlencoded';
        body = new URLSearchParams(form).toString();
      } else body = undefined;
      const res = await fetch(url, { method: m, headers, body, redirect: 'manual' });
      this.absorb(res);
      if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.get('location')) {
        const next = new URL(res.headers.get('location'), url).href;
        if (new URL(next).origin !== new URL(url).origin) {
          // left the PS (e.g. callback redirect): treat the PS side as finished
          return { status: res.status, url: next, text: '', offsite: true };
        }
        url = next;
        if (res.status <= 303) {
          m = 'GET';
          form = undefined;
        }
        continue;
      }
      return { status: res.status, url, text: await res.text() };
    }
    throw new Error('Too many redirects');
  }
}

function formFor(page, predicate) {
  return scan(page.text).forms.find(predicate);
}
function hiddenFields(form) {
  const out = [];
  for (const i of form.inputs) if ((i.type || '').toLowerCase() === 'hidden' && i.name) out.push([i.name, i.value ?? '']);
  return out;
}
async function submit(browser, page, form, fields) {
  const action = form.attrs.action ? new URL(form.attrs.action, page.url).href : page.url;
  return browser.go((form.attrs.method || 'post').toUpperCase(), action, [...hiddenFields(form), ...fields]);
}
const hasInput = (name) => (f) => f.inputs.some((i) => i.name === name);
const hasDecision = (value) => (f) => f.buttons.some((b) => b.name === 'decision' && b.value === value);

/**
 * Act as the person on the pending request `code`. plan: { email, password, decision, always,
 * onConsent(info) -> 'allow'|'deny' }. Returns { result, trail, consents }.
 */
export async function personAct(browser, interactUrl, code, plan) {
  const trail = [];
  const consents = [];
  let page = await browser.go('GET', `${interactUrl}?code=${encodeURIComponent(code)}`);
  for (let i = 0; i < 8; i++) {
    if (page.offsite) return { result: 'redirected', trail, consents, callback: page.url };
    const s = scan(page.text);
    trail.push(s.state || `?${page.status}`);
    vlog(`person(${browser.name}) page state=${s.state} status=${page.status}${s.error ? ` error="${s.error}"` : ''}`);
    let f;
    switch (s.state) {
      case 'code':
        if (trail.filter((t) => t === 'code').length > 1) throw new Error(`code rejected: ${s.error}`);
        f = formFor(page, hasInput('code'));
        if (!f) throw new Error('code form not found');
        page = await submit(browser, page, f, [['code', code]]);
        break;
      case 'signin':
        if (trail.filter((t) => t === 'signin').length > 1) throw new Error(`sign-in failed: ${s.error}`);
        f = formFor(page, hasInput('password'));
        if (!f) throw new Error('sign-in form not found');
        page = await submit(browser, page, f, [
          ['email', plan.email],
          ['password', plan.password],
        ]);
        break;
      case 'identity': {
        const d = plan.identityDecision || 'allow';
        f = formFor(page, hasDecision(d));
        if (!f) throw new Error(`identity form with decision=${d} not found`);
        page = await submit(browser, page, f, [['decision', d]]);
        break;
      }
      case 'consent': {
        const info = { scopes: s.scopes, error: s.error, allowDisabled: false };
        const allowBtn = s.forms.flatMap((x) => x.buttons).find((b) => b.name === 'decision' && b.value === 'allow');
        info.allowDisabled = !allowBtn || 'disabled' in allowBtn;
        consents.push(info);
        const d = plan.onConsent ? plan.onConsent(info) : plan.decision || 'allow';
        f = formFor(page, hasDecision(d));
        if (!f) throw new Error(`consent form with decision=${d} not found`);
        const fields = [['decision', d]];
        if (plan.always && d === 'allow') fields.push(['always', '1']);
        // per-scope checkboxes, inside the form or associated from elsewhere on the page
        const scopeInputs = f.inputs.some((i) => i.name === 'scopes[]') ? f.inputs : tags(page.text, 'input');
        for (const inp of scopeInputs) {
          if (inp.name === 'scopes[]' && !('disabled' in inp)) fields.push(['scopes[]', inp.value]);
        }
        page = await submit(browser, page, f, fields);
        break;
      }
      case 'next':
        return { result: 'approved', trail, consents };
      case 'done':
        return { result: s.result, trail, consents };
      default:
        throw new Error(`unrecognised page (HTTP ${page.status}${s.error ? `, error "${s.error}"` : ''}): ${page.text.replace(/\s+/g, ' ').slice(0, 200)}`);
    }
  }
  throw new Error(`no terminal state after ${trail.join(' > ')}`);
}


// ---------------------------------------------------------------------------
// CLI (for test harnesses in other languages, e.g. clients/python/tests/live_dreamfactory.py)
// ---------------------------------------------------------------------------
async function cli(argv) {
  const [cmd, url, code, ...rest] = argv;
  const flag = (n) => rest.includes(n);
  const opt = (n) => (rest.includes(n) ? rest[rest.indexOf(n) + 1] : undefined);
  if (cmd !== 'approve' || !url || !code || !opt('--email')) {
    process.stderr.write('usage: node person.mjs approve <interaction-url> <code> --email <email> [--deny] [--always]\n       password from $AAUTH_PERSON_PASSWORD\n');
    return 2;
  }
  const password = process.env.AAUTH_PERSON_PASSWORD;
  if (!password) {
    process.stderr.write('AAUTH_PERSON_PASSWORD is not set\n');
    return 2;
  }
  const decision = flag('--deny') ? 'deny' : 'allow';
  const act = await personAct(new Browser('cli'), url, code, { email: opt('--email'), password, decision, identityDecision: decision, always: flag('--always') });
  process.stdout.write(`${JSON.stringify({ result: act.result, trail: act.trail, scopes: act.consents.flatMap((c) => c.scopes) })}\n`);
  const wanted = decision === 'allow' ? ['approved', 'redirected'] : ['denied', 'redirected'];
  return wanted.includes(act.result) ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  cli(process.argv.slice(2)).then(
    (c) => process.exit(c),
    (e) => {
      process.stderr.write(`${e.message}\n`);
      process.exit(1);
    },
  );
}

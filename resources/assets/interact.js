// AAuth consent: after an identity approval, wait for the agent's follow-up request and open it.
(function () {
  var card = document.querySelector('[data-aauth-state="next"]');
  if (!card) return;
  var url = card.getAttribute('data-next-url');
  var live = card.querySelector('[data-aauth-live]');
  var wait = card.querySelector('[data-aauth-wait]');
  var closed = card.querySelector('[data-aauth-closed]');
  var heading = card.querySelector('[data-aauth-closed-heading]');
  var closedText = card.querySelector('[data-aauth-closed-text]');
  var badge = card.querySelector('[data-aauth-badge]');
  var stopped = false;
  var errors = 0;
  var MAX_ERRORS = 5;

  // Swap the waiting card for the outcome: the agent's tile with a badge, a heading, and a line
  // only when something went wrong (the line is hidden while empty).
  function stop(state, title, text, mark) {
    stopped = true;
    card.setAttribute('data-aauth-state', state);
    if (heading) heading.textContent = title;
    if (closedText) closedText.textContent = text;
    if (badge) badge.setAttribute('class', 'badge' + (mark ? ' ' + mark : ''));
    if (wait) wait.hidden = true;
    if (live) live.hidden = true;
    if (closed) closed.hidden = false;
  }

  function finish(approved) {
    card.setAttribute('data-aauth-result', approved ? 'approved' : 'denied');
    stop('done', approved ? 'Approved' : 'Denied', '', approved ? 'ok' : 'no');
  }

  function failed() {
    errors++;
    if (errors >= MAX_ERRORS) {
      stop('error', 'Something went wrong', 'This page lost contact with DreamFactory. Check the agent, then close this tab.');
      return;
    }
    setTimeout(tick, 3000);
  }

  function tick() {
    if (stopped) return;
    fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (d) {
        errors = 0;
        if (d.state === 'consent' && d.url) { stopped = true; window.location.assign(d.url); return; }
        if (d.state === 'done') { finish(d.result === 'approved'); return; }
        if (d.state === 'timeout') {
          stop('timeout', 'Request expired', 'The agent did not follow up in time. Nothing more was shared.');
          return;
        }
        setTimeout(tick, 1500);
      })
      .catch(failed);
  }
  setTimeout(tick, 1500);
})();

// AAuth single sign-on landing (/aauth/interact/sso): DreamFactory's login page sends the person
// back here with the one-time state and their session token in the URL fragment (or the query).
// Move both into the CSRF-protected POST, and scrub them from the address bar and history first.
(function () {
  var form = document.querySelector('form[data-aauth-sso]');
  if (!form) return;
  var found = {};
  [window.location.hash, window.location.search].forEach(function (part) {
    (part || '').split(/[#?&]/).forEach(function (pair) {
      var i = pair.indexOf('=');
      if (i < 1) return;
      var key = pair.slice(0, i);
      if ((key === 'state' || key === 'session_token') && !found[key]) {
        try { found[key] = decodeURIComponent(pair.slice(i + 1)); } catch (e) { /* malformed: ignore */ }
      }
    });
  });
  try { window.history.replaceState(null, '', window.location.pathname); } catch (e) { /* old browser */ }
  if (!found.state || !found.session_token) {
    var err = document.querySelector('[data-aauth-sso-error]');
    var wait = form.querySelector('[data-aauth-wait]');
    if (wait) wait.hidden = true;
    if (err) err.hidden = false;
    return;
  }
  form.elements.state.value = found.state;
  form.elements.session_token.value = found.session_token;
  form.submit();
})();

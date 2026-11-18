<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<?php if (!empty($refresh)): ?><meta http-equiv="refresh" content="1;url=<?= $e($refresh) ?>"><?php endif; ?>
<title><?= $e($title ?? 'DreamFactory') ?></title>
<link rel="icon" href="/dreamfactory/dist/favicon.ico">
<style>
@font-face{font-family:Inter;font-style:normal;font-weight:100 900;font-display:swap;src:url('/dreamfactory/dist/assets/fonts/Inter/Inter-VariableFont_slnt,wght.ttf') format('truetype')}
/* The admin's --df-* tokens (df-admin-interface styles.scss), light then dark. --btn is the platform's
   filled primary: navy in light (DF's login page, the admin's Approve); in dark a deeper accent so the
   white label clears AA. */
:root{color-scheme:light;--bg:#f5f5f7;--surface:#fff;--surface-2:rgba(0,0,0,.04);--hover:rgba(0,0,0,.04);--text:rgba(0,0,0,.87);--text-2:rgba(0,0,0,.7);--muted:rgba(0,0,0,.55);--faint:rgba(0,0,0,.4);--line:rgba(0,0,0,.12);--line-2:rgba(0,0,0,.08);--accent:#5c5699;--accent-strong:#423c89;--accent-ink:#fff;--btn:#0f0761;--btn-hover:#29227a;--accent-soft:rgba(92,86,153,.1);--link:#5c5699;--danger:#b3261e;--danger-soft:rgba(179,38,30,.08);--danger-border:rgba(179,38,30,.35);--success:#1a7f37;--success-soft:rgba(26,127,55,.1);--radius:8px;--radius-sm:6px;--mono:'SFMono-Regular',ui-monospace,'JetBrains Mono',Menlo,Consolas,monospace;--ease:cubic-bezier(.2,0,0,1)}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#121118;--surface:#1c1b21;--surface-2:rgba(255,255,255,.06);--hover:rgba(255,255,255,.06);--text:rgba(255,255,255,.9);--text-2:rgba(255,255,255,.7);--muted:rgba(255,255,255,.55);--faint:rgba(255,255,255,.4);--line:rgba(255,255,255,.1);--line-2:rgba(255,255,255,.08);--accent:#7571a9;--accent-strong:#908cba;--accent-ink:#fff;--btn:#6a66a0;--btn-hover:#7571a9;--accent-soft:rgba(144,140,186,.16);--link:#a9a5d6;--danger:#ff8a80;--danger-soft:rgba(220,53,69,.14);--danger-border:rgba(220,53,69,.45);--success:#4ade80;--success-soft:rgba(74,222,128,.14)}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:400 14px/1.5 Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
main{min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:32px 16px}
.card{width:100%;max-width:400px;background:var(--surface);border:1px solid var(--line-2);border-radius:var(--radius);padding:24px}
.card.wide{max-width:600px}
code,.mono{font-family:var(--mono)}
h1{font-size:20px;line-height:1.3;letter-spacing:-.011em;font-weight:600;margin:0;overflow-wrap:anywhere}
p{margin:0}
.muted{color:var(--muted)}
[hidden]{display:none!important}

/* top row: the wordmark, and the code the person matches against the agent's */
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;min-height:30px;margin:0 0 24px}
.logo{display:block;height:22px;width:auto}
.code{font:600 16px/1 var(--mono);letter-spacing:.06em;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:var(--radius-sm);padding:6px 8px 6px 10px;white-space:nowrap}

/* who is asking: tile, name, verified id, and its own words */
.agent{display:flex;align-items:center;gap:14px}
.agent-text{min-width:0}
.agent-id{font:12px/1.45 var(--mono);color:var(--muted);margin-top:3px;overflow-wrap:anywhere}
.agent-id code{font:inherit}
h1.agent-id-only{font:600 15px/1.4 var(--mono);letter-spacing:0}
.host{display:inline-block;max-width:100%}
.tile{flex:none;display:inline-grid;place-items:center;width:44px;height:44px;border-radius:var(--radius);background:var(--surface-2);border:1px solid var(--line-2);color:var(--text-2);font-weight:600;font-size:18px;line-height:1;user-select:none}
.tile svg{display:block;width:30px;height:30px}
blockquote.why{margin:14px 0 0 58px;padding:1px 0 1px 12px;border-left:2px solid var(--line);color:var(--text-2);white-space:pre-wrap;overflow-wrap:anywhere}

/* what it wants: the resource, and the scopes on it */
.panel{border:1px solid var(--line);border-radius:var(--radius);margin:20px 0 0;overflow:hidden}
.panel-head{display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--surface-2);border-bottom:1px solid var(--line-2)}
.panel-head:last-child{border-bottom:0}
.panel-head svg{flex:none;color:var(--muted)}
.res{min-width:0;display:flex;flex-wrap:wrap;align-items:baseline;column-gap:8px}
.res b{font-weight:600}
.res code{font-size:12px;color:var(--muted);overflow-wrap:anywhere}
ul.scopes{list-style:none;margin:0;padding:0}
ul.scopes li+li{border-top:1px solid var(--line-2)}
ul.scopes label{display:flex;gap:12px;align-items:flex-start;padding:12px 14px;cursor:pointer}
ul.scopes li.yes label:hover{background:var(--hover)}
ul.scopes li.no label{cursor:default}
.scope-text{min-width:0;display:flex;flex-direction:column;gap:2px}
.scope-text .d{font-weight:500}
.scope-text code{font-size:12px;color:var(--muted);overflow-wrap:anywhere}
ul.scopes li.no .d{color:var(--muted)}
.lacks{display:flex;align-items:center;gap:6px;margin-top:4px;font-size:12px;font-weight:500;color:var(--danger)}
.lacks svg{flex:none}
input[type=checkbox]{flex:none;width:16px;height:16px;margin:2px 0 0;accent-color:var(--accent);cursor:inherit}
.check{display:inline-flex;gap:10px;align-items:center;margin:16px 0 0;cursor:pointer}
.check input{margin:0}

/* who is answering */
.person{display:flex;align-items:center;gap:12px;min-width:0}
.panel .person{padding:12px 14px}
.avatar{flex:none;display:inline-grid;place-items:center;width:32px;height:32px;border-radius:50%;background:var(--accent-soft);color:var(--accent-strong);font-weight:600;font-size:13px;user-select:none}
.who{flex:1;min-width:0;display:flex;flex-direction:column}
.who b{font-weight:500;overflow-wrap:anywhere}
.who span{font-size:12px;color:var(--muted);overflow-wrap:anywhere}
.footer{margin:20px 0 0;padding:16px 0 0;border-top:1px solid var(--line-2)}

/* actions */
.actions{display:flex;gap:8px;justify-content:flex-end;align-items:center;margin:20px 0 0}
.footer .actions{margin-top:16px}
.actions button{min-width:0;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
button{font:500 14px/1 Inter,system-ui,sans-serif;height:40px;padding:0 18px;border-radius:var(--radius-sm);border:1px solid var(--line);background:var(--surface);color:var(--text);cursor:pointer;transition:background-color .15s var(--ease),border-color .15s var(--ease)}
button:hover{background:var(--hover)}
button.primary{background:var(--btn);border-color:var(--btn);color:var(--accent-ink)}
button.primary:hover{background:var(--btn-hover);border-color:var(--btn-hover)}
button.link{flex:none;height:auto;border:0;background:none;padding:4px 2px;color:var(--link)}
button.link:hover{background:none;text-decoration:underline;text-underline-offset:3px}
button[disabled]{opacity:.45;cursor:not-allowed}
button.primary[disabled],button.primary[disabled]:hover{background:var(--btn);border-color:var(--btn)}
button.full{width:100%}
.deny-row{display:flex;justify-content:center;margin:16px 0 0}
.sso-row{margin:10px 0 0}
:focus-visible{outline:none;box-shadow:0 0 0 2px var(--surface),0 0 0 4px var(--accent);border-radius:var(--radius-sm)}
input[type=checkbox]:focus-visible{border-radius:3px}

/* forms */
form.fields{margin:20px 0 0}
.field{display:block;margin:0 0 14px}
.field>span{display:block;font-size:13px;font-weight:500;color:var(--text-2);margin:0 0 6px}
input[type=text],input[type=email],input[type=password],.field select{display:block;width:100%;height:40px;padding:0 12px;border:1px solid var(--line);border-radius:var(--radius-sm);background:var(--surface);color:var(--text);font:inherit;transition:border-color .15s var(--ease)}
input[type=text]:hover,input[type=email]:hover,input[type=password]:hover,.field select:hover{border-color:var(--faint)}
input[type=text]:focus,input[type=email]:focus,input[type=password]:focus,.field select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}
input::placeholder{color:var(--faint)}
input.code-input{height:56px;font:600 24px/1 var(--mono);letter-spacing:.12em;text-align:center;text-transform:uppercase;padding:0 0 0 .12em}
input.code-input::placeholder{letter-spacing:.12em}
.field+button.full{margin-top:6px}

/* errors and states */
.error{display:flex;gap:10px;align-items:flex-start;margin:16px 0 0;padding:10px 12px;border:1px solid var(--danger-border);border-radius:var(--radius-sm);background:var(--danger-soft);color:var(--danger);font-size:13px;font-weight:500}
.error svg{flex:none;margin-top:1px}
.wait{display:flex;align-items:center;gap:12px;padding:14px;color:var(--text-2)}
.spinner{flex:none;width:18px;height:18px;border:2px solid var(--line);border-top-color:var(--accent);border-radius:50%;animation:spin .9s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.result{display:flex;flex-direction:column;align-items:center;text-align:center;padding:12px 0 4px}
.result h1{margin:18px 0 4px}
.result p:empty{display:none}
.mark{position:relative;display:inline-block}
.mark .tile{width:56px;height:56px;font-size:22px}
.mark .tile svg{width:38px;height:38px}
.badge{position:absolute;right:-7px;bottom:-7px;display:grid;place-items:center;width:24px;height:24px;border-radius:50%;border:2px solid var(--surface);color:#fff}
.badge.ok{background:var(--success)}
.badge.no{background:var(--danger)}
.badge.ok .i-no,.badge.no .i-ok,.badge:not(.ok):not(.no){display:none}
@media (prefers-color-scheme:dark){.badge{color:#121118}}

/* /aauth/grants */
.grant-list{list-style:none;margin:20px 0 0;padding:0;border:1px solid var(--line);border-radius:var(--radius)}
.grant-list li{display:grid;grid-template-columns:36px minmax(0,1fr) auto;column-gap:14px;align-items:start;padding:14px}
.grant-list li+li{border-top:1px solid var(--line-2)}
.grant-list .tile{width:36px;height:36px;font-size:15px}
.grant-list .tile svg{width:24px;height:24px}
.grant-main{flex:1;min-width:0}
.grant-main b{font-weight:600;overflow-wrap:anywhere}
.grant-on{display:flex;flex-wrap:wrap;align-items:center;gap:6px;min-width:0;margin-top:8px;font-size:13px;color:var(--text-2)}
.grant-on svg{flex:none;color:var(--muted)}
.chip{display:inline-block;max-width:100%;overflow-wrap:anywhere;font:12px/1.5 var(--mono);padding:1px 7px;border-radius:var(--radius-sm);background:var(--surface-2);border:1px solid var(--line-2);color:var(--text-2)}
.grant-list button{height:32px;padding:0 12px;font-size:13px}
.grant-list button[value=revoke]{color:var(--danger);border-color:var(--danger-border)}
.grant-list button[value=revoke]:hover{background:var(--danger-soft)}
.empty{margin:20px 0 0;padding:20px;border:1px dashed var(--line);border-radius:var(--radius);text-align:center;color:var(--muted)}
.signed{margin:16px 0 0}

@media (max-width:480px){
  main{place-items:start center;padding:16px}
  .card{padding:20px}
  .top{margin-bottom:20px}
  blockquote.why{margin-left:0}
  .footer .actions{display:grid;grid-template-columns:minmax(96px,auto) minmax(0,1fr)}
  .grant-list li{grid-template-columns:36px minmax(0,1fr)}
  .grant-list form{grid-column:2;margin-top:12px}
}
@media (prefers-reduced-motion:reduce){
  .spinner{animation-duration:2.4s}
  button,input{transition:none}
}
</style>
</head>
<body>
<main>
<div class="card<?= !empty($wide) ? ' wide' : '' ?>"<?= $attrs ?? '' ?>>
<div class="top">
<img class="logo" src="/dreamfactory/dist/assets/img/logo.png" alt="DreamFactory" width="122" height="22">
<?php if (!empty($code)): ?><span class="code" aria-label="Code <?= $e($code) ?>"><?= $e($code) ?></span><?php endif; ?>
</div>
<?= $content ?>
</div>
</main>
<?php if (!empty($script)): ?><script src="/aauth/assets/interact.js" defer></script><?php endif; ?>
</body>
</html>

<h1>Signing you in</h1>
<?php include __DIR__ . '/_error.php'; ?>
<p class="error" role="alert" data-aauth-sso-error hidden><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5M12 16.5h.01"/></svg>Single sign-on did not complete. Go back to the agent's code and try again.</p>
<form method="post" action="<?= $e($ssoPath) ?>" data-aauth-sso>
<input type="hidden" name="_token" value="<?= $e($csrf) ?>">
<input type="hidden" name="state" value="">
<input type="hidden" name="session_token" value="">
<div class="wait" data-aauth-wait role="status"><span class="spinner" aria-hidden="true"></span>One moment</div>
<noscript><p class="muted">Turn on JavaScript to finish signing in.</p></noscript>
</form>

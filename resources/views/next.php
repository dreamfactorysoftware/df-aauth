<div data-aauth-live>
<?php include __DIR__ . '/_agent.php'; ?>
<div class="panel">
<?php include __DIR__ . '/_resource.php'; ?>
<div class="wait" data-aauth-wait role="status"><span class="spinner" aria-hidden="true"></span>Waiting for the agent</div>
</div>
</div>
<div class="result" data-aauth-closed hidden>
<span class="mark"><?= $tile($heading, !empty($agentPlayground)) ?><span class="badge" data-aauth-badge><svg class="i-ok" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg><svg class="i-no" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" aria-hidden="true"><path d="M7 7l10 10M17 7L7 17"/></svg></span></span>
<h1 data-aauth-closed-heading>Done</h1>
<p class="muted" data-aauth-closed-text></p>
</div>

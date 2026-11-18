<div class="result">
<span class="mark"><?= $tile($heading ?? 'Agent', !empty($agentPlayground)) ?><span class="badge <?= $approved ? 'ok' : 'no' ?>"><?= $approved
    ? '<svg class="i-ok" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>'
    : '<svg class="i-no" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" aria-hidden="true"><path d="M7 7l10 10M17 7L7 17"/></svg>' ?></span></span>
<h1><?= $approved ? 'Approved' : 'Denied' ?></h1>
</div>

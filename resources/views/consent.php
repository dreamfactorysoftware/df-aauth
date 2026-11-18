<?php include __DIR__ . '/_agent.php'; ?>
<?php include __DIR__ . '/_error.php'; ?>
<form method="post" action="/aauth/interact">
<input type="hidden" name="_token" value="<?= $e($csrf) ?>">
<input type="hidden" name="pid" value="<?= $e($pid) ?>">
<input type="hidden" name="scopes_shown" value="1">
<div class="panel">
<?php include __DIR__ . '/_resource.php'; ?>
<ul class="scopes">
<?php foreach ($scopes as $s): ?>
<li class="<?= $s['grantable'] ? 'yes' : 'no' ?>" data-aauth-scope="<?= $e($s['scope']) ?>" data-aauth-grantable="<?= $s['grantable'] ? '1' : '0' ?>">
<label><input type="checkbox" name="scopes[]" value="<?= $e($s['scope']) ?>"<?= $s['grantable'] ? ' checked' : ' disabled' ?>>
<span class="scope-text"><span class="d"><?= $e($s['description']) ?></span><code><?= $e($s['scope']) ?></code><?php if (!$s['grantable']): ?><span class="lacks"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>You don't have this role</span><?php endif; ?></span></label>
</li>
<?php endforeach; ?>
</ul>
</div>
<?php if ($anyGrantable): ?><label class="check"><input type="checkbox" name="always" value="1">Always allow</label><?php endif; ?>
<div class="footer">
<?php if (!empty($userName)): ?>
<div class="person" data-aauth-user>
<?= $avatar($userName) ?>
<div class="who"><b><?= $ident($userName) ?></b><?php if (($userEmail ?? '') !== $userName): ?><span><?= $ident($userEmail) ?></span><?php endif; ?></div>
<button class="link" type="submit" name="decision" value="switch" formnovalidate>Not you?</button>
</div>
<?php endif; ?>
<div class="actions">
<button<?= $anyGrantable ? '' : ' class="primary"' ?> type="submit" name="decision" value="deny">Deny</button>
<button<?= $anyGrantable ? ' class="primary"' : '' ?> type="submit" name="decision" value="allow"<?= $anyGrantable ? '' : ' disabled' ?>>Allow</button>
</div>
</div>
</form>

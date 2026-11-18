<h1>Agent access</h1>
<?php include __DIR__ . '/_error.php'; ?>
<form method="post" action="/aauth/grants" class="person signed">
<input type="hidden" name="_token" value="<?= $e($csrf) ?>">
<?= $avatar($userName) ?>
<div class="who"><b><?= $ident($userName) ?></b><?php if ($userEmail !== $userName): ?><span><?= $ident($userEmail) ?></span><?php endif; ?></div>
<button class="link" type="submit" name="decision" value="signout">Sign out</button>
</form>
<?php if (!$grants): ?>
<p class="empty">No agents have standing access.</p>
<?php else: ?>
<ul class="grant-list">
<?php foreach ($grants as $g): ?>
<li data-aauth-grant="<?= $e($g['id']) ?>">
<?= $tile($g['agent_name'] ?: $g['agent_sub'], !empty($g['playground'])) ?>
<div class="grant-main">
<b<?= $g['agent_name'] ? '' : ' class="mono"' ?>><?= $g['agent_name'] ? $e($g['agent_name']) : $ident($g['agent_sub']) ?></b>
<?php if ($g['agent_name']): ?><p class="agent-id"><code><?= $ident($g['agent_sub']) ?></code></p><?php endif; ?>
<div class="grant-on"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg><span><?= $e($g['resource_name'] ?: $g['resource_host']) ?></span><?php foreach ($g['scopes'] as $s): ?><span class="chip"><?= $e($s) ?></span><?php endforeach; ?></div>
</div>
<form method="post" action="/aauth/grants"><input type="hidden" name="_token" value="<?= $e($csrf) ?>"><input type="hidden" name="grant_id" value="<?= $e($g['id']) ?>"><button type="submit" name="decision" value="revoke">Revoke</button></form>
</li>
<?php endforeach; ?>
</ul>
<?php endif; ?>

<?php include __DIR__ . '/_agent.php'; ?>
<?php include __DIR__ . '/_error.php'; ?>
<form method="post" action="/aauth/interact">
<input type="hidden" name="_token" value="<?= $e($csrf) ?>">
<input type="hidden" name="pid" value="<?= $e($pid) ?>">
<div class="panel">
<?php include __DIR__ . '/_resource.php'; ?>
</div>
<div class="footer">
<div class="person" data-aauth-user>
<?= $avatar($userName) ?>
<div class="who"><b><?= $ident($userName) ?></b><?php if ($userEmail !== $userName): ?><span><?= $ident($userEmail) ?></span><?php endif; ?></div>
<button class="link" type="submit" name="decision" value="switch">Not you?</button>
</div>
<div class="actions">
<button type="submit" name="decision" value="deny">Deny</button>
<button class="primary" type="submit" name="decision" value="allow"><?= !empty($userFirst) ? 'Continue as ' . $e($userFirst) : 'Continue' ?></button>
</div>
</div>
</form>

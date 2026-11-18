<?php if (!empty($agentSub)): ?>
<?php include __DIR__ . '/_agent.php'; ?>
<?php else: ?>
<h1><?= $e($heading) ?></h1>
<?php endif; ?>
<?php include __DIR__ . '/_error.php'; ?>
<?php $dirs = $directories ?? []; $byName = ($loginAttribute ?? 'email') === 'username'; ?>
<form class="fields" method="post" action="<?= $e($action ?? '/aauth/interact') ?>">
<input type="hidden" name="_token" value="<?= $e($csrf) ?>">
<?php if (!empty($pid)): ?><input type="hidden" name="pid" value="<?= $e($pid) ?>"><?php endif; ?>
<?php if ($dirs): ?><label class="field"><span>Sign in with</span><select name="service"><option value="">DreamFactory account</option><?php foreach ($dirs as $d): ?><option value="<?= $e($d['name']) ?>"<?= strcasecmp((string)($service ?? ''), $d['name']) === 0 ? ' selected' : '' ?>><?= $e($d['label']) ?></option><?php endforeach; ?></select></label><?php endif; ?>
<label class="field"><span><?= $dirs ? 'Email or username' : ($byName ? 'Username' : 'Email') ?></span><input type="<?= $dirs || $byName ? 'text' : 'email' ?>" name="email" autocomplete="username" value="<?= $e($email ?? '') ?>" required<?= empty($email) ? ' autofocus' : '' ?>></label>
<label class="field"><span>Password</span><input type="password" name="password" autocomplete="current-password" required<?= empty($email) ? '' : ' autofocus' ?>></label>
<button class="primary full" type="submit">Sign in</button>
</form>
<?php if (!empty($sso)): ?>
<form method="post" action="<?= $e($action ?? '/aauth/interact') ?>" class="sso-row">
<input type="hidden" name="_token" value="<?= $e($csrf) ?>">
<?php if (!empty($pid)): ?><input type="hidden" name="pid" value="<?= $e($pid) ?>"><?php endif; ?>
<button class="full" type="submit" name="decision" value="sso">Sign in with single sign-on</button>
</form>
<?php endif; ?>
<?php if (!empty($canDeny) && !empty($pid)): ?>
<form method="post" action="/aauth/interact" class="deny-row">
<input type="hidden" name="_token" value="<?= $e($csrf) ?>">
<input type="hidden" name="pid" value="<?= $e($pid) ?>">
<button class="link" type="submit" name="decision" value="deny">Deny this request</button>
</form>
<?php endif; ?>

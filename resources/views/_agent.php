<?php /* Who is asking: tile (gear only for our own Playground), the name it gives, its verified id, its reason. */ ?>
<div class="agent" data-aauth-requester>
<?= $tile($heading, !empty($agentPlayground)) ?>
<div class="agent-text">
<?php if (!empty($agentSub) && ($heading === $agentSub || empty($agentNamed))): ?>
<h1 class="agent-id-only" data-aauth-agent="<?= $e($agentSub) ?>"><?= $ident($agentSub) ?></h1>
<?php else: ?>
<h1><?= $e($heading) ?></h1>
<?php if (!empty($agentSub)): ?><p class="agent-id" data-aauth-agent="<?= $e($agentSub) ?>"><code><?= $ident($agentSub) ?></code></p><?php endif; ?>
<?php endif; ?>
</div>
</div>
<?php if (!empty($justification)): ?><blockquote class="why"><?= $e($justification) ?></blockquote><?php endif; ?>

<h1>Enter the code</h1>
<?php include __DIR__ . '/_error.php'; ?>
<form class="fields" method="post" action="/aauth/interact" autocomplete="off">
<input type="hidden" name="_token" value="<?= $e($csrf) ?>">
<label class="field"><input class="code-input" type="text" name="code" placeholder="XXXX-XXXX" maxlength="12" value="<?= $e($value ?? '') ?>" autofocus required aria-label="Code" spellcheck="false" autocapitalize="characters"></label>
<button class="primary full" type="submit">Continue</button>
</form>

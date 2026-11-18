<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * aauth_ps_tokens: the agent each person and auth token of this DreamFactory's person server was
 * issued for (IssuedTokens), so the resource attributes those tokens to that agent rather than to the
 * signing key's latest agent token. Rows live until the token has expired (prune). Additive and
 * idempotent.
 */
return new class extends Migration {
    public function up(): void
    {
        if (!Schema::hasTable('aauth_ps_tokens')) {
            Schema::create('aauth_ps_tokens', function (Blueprint $t) {
                $t->string('jti', 64)->primary();
                $t->string('kind', 8);
                $t->string('agent_iss', 255);
                $t->string('agent_sub', 255);
                $t->string('agent_name', 255)->nullable();
                $t->unsignedBigInteger('expires_at');
                $t->timestamp('created_at')->nullable();
                $t->index(['expires_at'], 'aauth_ps_tokens_exp_idx');
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('aauth_ps_tokens');
    }
};

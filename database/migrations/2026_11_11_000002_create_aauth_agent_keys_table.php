<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * aauth_agent_keys: durable jkt -> agent (sub + agent provider) mapping, written whenever a key
 * presents an agent token to this DreamFactory (resource or local person server). Person and auth
 * tokens carry no agent claim, so blocks are enforced through it. Idempotent.
 */
return new class extends Migration {
    public function up(): void
    {
        if (!Schema::hasTable('aauth_agent_keys')) {
            Schema::create('aauth_agent_keys', function (Blueprint $t) {
                $t->string('jkt', 64)->primary();
                $t->string('agent_id', 255);
                $t->string('issuer', 255)->default('');
                $t->string('name', 255)->nullable();
                $t->timestamp('last_seen_at')->nullable();
                $t->index(['agent_id', 'issuer'], 'aauth_agent_keys_agent_idx');
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('aauth_agent_keys');
    }
};

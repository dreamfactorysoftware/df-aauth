<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * aauth_agent_keys keeps every agent a signing key has presented an agent token for (one row per key
 * and agent) instead of only the latest one, so blocking any of those agents reaches the key and the
 * person and auth tokens bound to it (Agents::rememberKey / identityForKey). The table is rebuilt
 * through a new one (portable: no primary key change in place) and the existing bindings are kept.
 * Idempotent, and safe to run again after an interrupted run.
 */
return new class extends Migration {
    private const KEYS = 'aauth_agent_keys';
    private const NEXT = 'aauth_agent_keys_v2';

    public function up(): void
    {
        if (!Schema::hasTable(self::KEYS) && Schema::hasTable(self::NEXT)) {
            Schema::rename(self::NEXT, self::KEYS); // an earlier run stopped after copying

            return;
        }
        if (Schema::hasTable(self::KEYS) && Schema::hasColumn(self::KEYS, 'id')) {
            Schema::dropIfExists(self::NEXT);

            return;
        }
        Schema::dropIfExists(self::NEXT); // an earlier run stopped before copying
        Schema::create(self::NEXT, function (Blueprint $t) {
            $t->increments('id');
            $t->string('jkt', 64);
            $t->string('agent_id', 255);
            $t->string('issuer', 255)->default('');
            $t->string('name', 255)->nullable();
            $t->timestamp('last_seen_at')->nullable();
            $t->unique(['jkt', 'agent_id', 'issuer'], 'aauth_agent_key_bindings_unique');
            $t->index(['agent_id', 'issuer'], 'aauth_agent_key_bindings_agent_idx');
        });
        if (Schema::hasTable(self::KEYS)) {
            $columns = ['jkt', 'agent_id', 'issuer', 'name', 'last_seen_at'];
            DB::table(self::NEXT)->insertUsing($columns, DB::table(self::KEYS)->select($columns));
            Schema::drop(self::KEYS);
        }
        Schema::rename(self::NEXT, self::KEYS);
    }

    /** Back to one row per key: the most recently seen binding of each key is kept. */
    public function down(): void
    {
        if (!Schema::hasTable(self::KEYS) || !Schema::hasColumn(self::KEYS, 'id')) {
            return;
        }
        $latest = [];
        foreach (DB::table(self::KEYS)->orderBy('last_seen_at')->orderBy('id')->get() as $row) {
            $latest[$row->jkt] = ['jkt' => $row->jkt, 'agent_id' => $row->agent_id, 'issuer' => $row->issuer,
                'name' => $row->name, 'last_seen_at' => $row->last_seen_at];
        }
        Schema::dropIfExists(self::NEXT);
        Schema::create(self::NEXT, function (Blueprint $t) {
            $t->string('jkt', 64)->primary();
            $t->string('agent_id', 255);
            $t->string('issuer', 255)->default('');
            $t->string('name', 255)->nullable();
            $t->timestamp('last_seen_at')->nullable();
            $t->index(['agent_id', 'issuer'], 'aauth_agent_keys_v1_agent_idx');
        });
        foreach (array_chunk(array_values($latest), 200) as $chunk) {
            DB::table(self::NEXT)->insert($chunk);
        }
        Schema::drop(self::KEYS);
        Schema::rename(self::NEXT, self::KEYS);
    }
};

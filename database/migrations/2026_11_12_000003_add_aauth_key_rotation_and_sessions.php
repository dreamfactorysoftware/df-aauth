<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Key rotation and shared consent sessions. Portable and idempotent, like the other df-aauth migrations.
 *  - aauth_keys.retired_at: key rotation (a retired key stays published for the overlap window).
 *  - aauth_sessions: Laravel's database session table, used by the consent and grants pages only
 *    when DF_AAUTH_SESSION_DRIVER=database (several DreamFactory nodes without redis or sticky sessions).
 */
return new class extends Migration {
    public function up(): void
    {
        if (Schema::hasTable('aauth_keys') && !Schema::hasColumn('aauth_keys', 'retired_at')) {
            Schema::table('aauth_keys', function (Blueprint $t) {
                $t->timestamp('retired_at')->nullable();
            });
        }
        if (!Schema::hasTable('aauth_sessions')) {
            Schema::create('aauth_sessions', function (Blueprint $t) {
                $t->string('id', 128)->primary();
                $t->unsignedInteger('user_id')->nullable();
                $t->string('ip_address', 45)->nullable();
                $t->text('user_agent')->nullable();
                $t->longText('payload');
                $t->integer('last_activity');
                $t->index(['last_activity'], 'aauth_sessions_activity_idx');
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('aauth_sessions');
        if (Schema::hasTable('aauth_keys') && Schema::hasColumn('aauth_keys', 'retired_at')) {
            Schema::table('aauth_keys', function (Blueprint $t) {
                $t->dropColumn('retired_at');
            });
        }
    }
};

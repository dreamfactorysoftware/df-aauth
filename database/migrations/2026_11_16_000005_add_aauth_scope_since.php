<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * aauth_scopes.scope_since: when the role took its scope name (unix seconds; set when the row is
 * created and on every rename). An auth token issued before then was issued for an earlier holder of
 * the name, so its grant of that name is ignored (Scopes::heldAt). Null for rows created before this
 * migration: no constraint. Additive and idempotent.
 */
return new class extends Migration {
    public function up(): void
    {
        if (Schema::hasTable('aauth_scopes') && !Schema::hasColumn('aauth_scopes', 'scope_since')) {
            Schema::table('aauth_scopes', function (Blueprint $t) {
                $t->unsignedBigInteger('scope_since')->nullable();
            });
        }
    }

    public function down(): void
    {
        if (Schema::hasTable('aauth_scopes') && Schema::hasColumn('aauth_scopes', 'scope_since')) {
            Schema::table('aauth_scopes', function (Blueprint $t) {
                $t->dropColumn('scope_since');
            });
        }
    }
};

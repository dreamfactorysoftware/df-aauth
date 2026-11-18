<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * df-aauth system tables. Portable (MySQL/MariaDB, PostgreSQL, SQLite, SQL Server): Schema builder
 * only, JSON in text columns, short explicit index/FK names. Idempotent: every create is guarded.
 */
return new class extends Migration {
    private const TABLES = [
        'aauth_settings', 'aauth_keys', 'aauth_scopes', 'aauth_person_servers', 'aauth_agents',
        'aauth_activity', 'aauth_ps_pending', 'aauth_ps_grants', 'aauth_ps_subjects',
    ];

    public function up(): void
    {
        if (!Schema::hasTable('aauth_settings')) {
            Schema::create('aauth_settings', function (Blueprint $t) {
                $t->string('name', 64)->primary();
                $t->text('value')->nullable();
                $t->timestamp('updated_at')->nullable();
            });
        }
        if (!Schema::hasTable('aauth_keys')) {
            Schema::create('aauth_keys', function (Blueprint $t) {
                $t->increments('id');
                $t->string('purpose', 16);
                $t->string('kid', 64);
                $t->text('public_jwk');
                $t->text('private_jwk');
                $t->boolean('active')->default(true);
                $t->timestamp('created_at')->nullable();
                $t->index(['purpose', 'active'], 'aauth_keys_purpose_idx');
            });
        }
        if (!Schema::hasTable('aauth_scopes')) {
            Schema::create('aauth_scopes', function (Blueprint $t) {
                $t->increments('id');
                $t->unsignedInteger('role_id');
                $t->string('scope', 64);
                $t->text('description')->nullable();
                $t->boolean('enabled')->default(false);
                $t->timestamp('created_at')->nullable();
                $t->timestamp('updated_at')->nullable();
                $t->unique(['role_id'], 'aauth_scopes_role_unique');
                $t->unique(['scope'], 'aauth_scopes_scope_unique');
                $t->foreign('role_id', 'aauth_scopes_role_fk')->references('id')->on('role')->onDelete('cascade');
            });
        }
        if (!Schema::hasTable('aauth_person_servers')) {
            Schema::create('aauth_person_servers', function (Blueprint $t) {
                $t->increments('id');
                $t->string('issuer', 255);
                $t->string('name', 255)->nullable();
                $t->boolean('is_local')->default(false);
                $t->boolean('enabled')->default(true);
                $t->text('scopes')->nullable();
                $t->timestamp('last_used_at')->nullable();
                $t->timestamp('created_at')->nullable();
                $t->timestamp('updated_at')->nullable();
                $t->unique(['issuer'], 'aauth_ps_issuer_unique');
            });
        }
        if (!Schema::hasTable('aauth_agents')) {
            Schema::create('aauth_agents', function (Blueprint $t) {
                $t->increments('id');
                $t->string('agent_id', 255);
                $t->string('issuer', 255)->default('');
                $t->string('name', 255)->nullable();
                $t->string('status', 16)->default('allowed');
                $t->timestamp('first_seen_at')->nullable();
                $t->timestamp('last_seen_at')->nullable();
                $t->unsignedInteger('request_count')->default(0);
                $t->unique(['agent_id', 'issuer'], 'aauth_agents_id_iss_unique');
            });
        }
        if (!Schema::hasTable('aauth_activity')) {
            Schema::create('aauth_activity', function (Blueprint $t) {
                $t->bigIncrements('id');
                $t->timestamp('created_at')->nullable();
                $t->unsignedInteger('agent_row_id')->nullable();
                $t->string('agent_id', 255)->nullable();
                $t->string('ps_issuer', 255)->nullable();
                $t->string('person_sub', 255)->nullable();
                $t->unsignedInteger('user_id')->nullable();
                $t->string('scope', 255)->nullable();
                $t->string('method', 12);
                $t->string('path', 512);
                $t->unsignedSmallInteger('status');
                $t->string('outcome', 24);
                $t->string('detail', 255)->nullable();
                $t->index(['created_at'], 'aauth_activity_created_idx');
            });
        }
        if (!Schema::hasTable('aauth_ps_pending')) {
            Schema::create('aauth_ps_pending', function (Blueprint $t) {
                $t->string('id', 32)->primary();
                $t->string('kind', 8);
                $t->string('code', 16);
                $t->string('status', 16);
                $t->text('agent');
                $t->string('resource', 255);
                $t->string('resource_name', 255)->nullable();
                $t->text('scope')->nullable();
                $t->text('scope_descriptions')->nullable();
                $t->text('justification')->nullable();
                $t->string('sub', 64)->nullable();
                $t->unsignedInteger('presented_exp')->nullable();
                $t->unsignedInteger('user_id')->nullable();
                $t->text('result')->nullable();
                $t->unsignedInteger('result_exp')->nullable();
                $t->timestamp('created_at')->nullable();
                $t->timestamp('expires_at')->nullable();
                $t->index(['code'], 'aauth_pending_code_idx');
                $t->index(['sub', 'kind'], 'aauth_pending_sub_idx');
            });
        }
        if (!Schema::hasTable('aauth_ps_grants')) {
            Schema::create('aauth_ps_grants', function (Blueprint $t) {
                $t->increments('id');
                $t->unsignedInteger('user_id');
                $t->string('resource', 255);
                $t->string('resource_name', 255)->nullable();
                $t->string('agent_iss', 255);
                $t->string('agent_sub', 255);
                $t->string('agent_name', 255)->nullable();
                $t->text('scope');
                $t->timestamp('created_at')->nullable();
                $t->timestamp('last_used_at')->nullable();
                $t->unique(['user_id', 'resource', 'agent_iss', 'agent_sub'], 'aauth_grants_unique');
            });
        }
        if (!Schema::hasTable('aauth_ps_subjects')) {
            Schema::create('aauth_ps_subjects', function (Blueprint $t) {
                $t->string('sub', 64)->primary();
                $t->unsignedInteger('user_id');
                $t->string('resource', 255);
                $t->timestamp('created_at')->nullable();
            });
        }
    }

    public function down(): void
    {
        foreach (array_reverse(self::TABLES) as $table) {
            Schema::dropIfExists($table);
        }
    }
};

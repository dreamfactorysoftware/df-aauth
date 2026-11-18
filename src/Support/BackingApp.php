<?php

namespace DreamFactory\Core\AAuth\Support;

use DreamFactory\Core\Models\App;
use Illuminate\Support\Facades\DB;

/**
 * The hidden app named `aauth` that AAuth sessions run under (no role, active). Script contexts
 * (Node/Python callbacks) re-derive the session from an app, so AAuth requests need one.
 */
final class BackingApp
{
    public const NAME = 'aauth';

    public static function id(): ?int
    {
        try {
            $id = Store::cache()->remember('aauth:app_id', 3600, function () {
                $id = DB::table('app')->where('name', self::NAME)->value('id');
                if ($id) {
                    return (int)$id;
                }
                $app = new App();
                $app->name = self::NAME;
                $app->description = 'AAuth agent sessions';
                $app->is_active = true;
                $app->type = 0;
                $app->api_key = App::generateApiKey(self::NAME);
                $app->save();

                return (int)$app->id;
            });

            return $id ? (int)$id : null;
        } catch (\Throwable $e) {
            return null;
        }
    }
}

#!/usr/bin/env bash
# df-aauth OFFLINE development install into a running DreamFactory container.
#
#   bin/dev-install.sh [container] [package-path-in-container]
#     container      default: dreamfactory_web_1
#     package path   default: /src/df-aauth  (bind-mount the package there)
#
# What it does (idempotent; safe to re-run after pulling changes):
#   1. symlinks vendor/dreamfactory/$NAME -> <package path>
#   2. registers the package in vendor/composer/installed.json (no network, no composer resolution)
#      and adds it to the root composer.json require (backup: composer.json.before-$NAME)
#   3. composer dump-autoload -o (runs package:discover through the post-autoload-dump hook);
#      rolls the registration back if the provider class does not autoload
#   4. php artisan migrate --force, cache:clear, config:clear
#   5. fixes storage/bootstrap cache ownership for php-fpm
#
# Generalized from df-masking's script: every package-specific value comes from the variables below
# and from the package's composer.json (name, autoload, extra.laravel.providers[0]).
#
# Environment: DOCKER (default "sudo -n docker" when not root, else "docker").
set -euo pipefail

CONTAINER="${1:-dreamfactory_web_1}"
PKG="${2:-/src/df-aauth}"
NAME=df-aauth                 # vendor/dreamfactory/<NAME>, backup suffix, log prefix
MIGRATION_TAG=_aauth_         # every migration file name contains it
HERE="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -z "${DOCKER:-}" ]]; then
  if [[ "$(id -u)" == "0" ]]; then DOCKER="docker"; else DOCKER="sudo -n docker"; fi
fi

say() { printf '[%s] %s\n' "$NAME" "$*"; }

if ! $DOCKER exec "$CONTAINER" test -f "$PKG/composer.json"; then
  echo "[$NAME] $PKG/composer.json not found in container $CONTAINER (bind-mount the package there)." >&2
  exit 1
fi

say "linking vendor/dreamfactory/$NAME -> $PKG"
$DOCKER exec -e PKG="$PKG" -e NAME="$NAME" "$CONTAINER" bash -euc '
  cd /opt/dreamfactory
  target=vendor/dreamfactory/$NAME
  if [ -L "$target" ] || [ -e "$target" ]; then
    if [ "$(readlink "$target" 2>/dev/null)" != "$PKG" ]; then rm -rf "$target"; fi
  fi
  [ -L "$target" ] || ln -s "$PKG" "$target"
'

say "registering the package in vendor/composer/installed.json"
$DOCKER exec -i "$CONTAINER" php -d display_errors=stderr -- /opt/dreamfactory/vendor/composer/installed.json "$NAME" "$PKG" <<'PHP'
<?php
[$file, $name, $pkgPath] = [$argv[1], $argv[2], $argv[3]];
$installed = json_decode(file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
$pkg = json_decode(file_get_contents("/opt/dreamfactory/vendor/dreamfactory/$name/composer.json"), true, 512, JSON_THROW_ON_ERROR);
$entry = [
    'name' => $pkg['name'],
    'version' => 'dev-develop',
    'version_normalized' => 'dev-develop',
    'dist' => ['type' => 'path', 'url' => '../../..' . $pkgPath, 'reference' => null],
    'require' => $pkg['require'] ?? [],
    'type' => 'library',
    'extra' => $pkg['extra'] ?? [],
    'autoload' => $pkg['autoload'] + [
        // Dev install only: keep src/ out of the optimized classmap so added/renamed files resolve via PSR-4.
        'exclude-from-classmap' => ['src/'],
    ],
    'license' => (array)($pkg['license'] ?? 'proprietary'),
    'description' => $pkg['description'] ?? '',
    'install-path' => "../dreamfactory/$name",
];
$list = isset($installed['packages']) ? $installed['packages'] : $installed;
$list = array_values(array_filter($list, fn ($p) => ($p['name'] ?? '') !== $entry['name']));
$list[] = $entry;
if (isset($installed['packages'])) {
    $installed['packages'] = $list;
    $installed['dev-package-names'] = array_values(array_filter($installed['dev-package-names'] ?? [], fn ($n) => $n !== $entry['name']));
} else {
    $installed = $list;
}
file_put_contents($file, json_encode($installed, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");

$rootFile = '/opt/dreamfactory/composer.json';
$root = json_decode(file_get_contents($rootFile), true, 512, JSON_THROW_ON_ERROR);
if (($root['require'][$entry['name']] ?? null) !== 'dev-develop') {
    if (!file_exists("$rootFile.before-$name")) {
        copy($rootFile, "$rootFile.before-$name");
    }
    $root['require'][$entry['name']] = 'dev-develop';
    file_put_contents($rootFile, json_encode($root, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
}
echo "ok\n";
PHP

COMPOSER_NAME="$($DOCKER exec "$CONTAINER" php -r "echo json_decode(file_get_contents('$PKG/composer.json'), true)['name'];")"
PROVIDER="$($DOCKER exec "$CONTAINER" php -r "echo json_decode(file_get_contents('$PKG/composer.json'), true)['extra']['laravel']['providers'][0];")"

say "composer dump-autoload -o (offline) + package:discover"
$DOCKER exec -e COMPOSER_ALLOW_SUPERUSER=1 "$CONTAINER" bash -euc '
  cd /opt/dreamfactory
  composer dump-autoload -o --no-interaction 2>&1 | tail -n 3
'
# Never leave the instance with a registered provider it cannot autoload (every request would 500).
if ! $DOCKER exec -e P="$PROVIDER" "$CONTAINER" php -r 'require "/opt/dreamfactory/vendor/autoload.php"; exit(class_exists(getenv("P")) ? 0 : 1);'; then
  echo "[$NAME] the package does not autoload; rolling the registration back" >&2
  $DOCKER exec -e COMPOSER_ALLOW_SUPERUSER=1 -e CN="$COMPOSER_NAME" -e NAME="$NAME" "$CONTAINER" bash -euc '
    cd /opt/dreamfactory
    php -r '"'"'
      $n = getenv("CN");
      $f = "vendor/composer/installed.json"; $j = json_decode(file_get_contents($f), true);
      $j["packages"] = array_values(array_filter($j["packages"], fn ($p) => ($p["name"] ?? "") !== $n));
      file_put_contents($f, json_encode($j, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
      $r = "composer.json"; $c = json_decode(file_get_contents($r), true); unset($c["require"][$n]);
      file_put_contents($r, json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    '"'"'
    rm -f "vendor/dreamfactory/$NAME"
    composer dump-autoload -o --no-interaction >/dev/null 2>&1
  '
  exit 1
fi
if ! $DOCKER exec -e P="$PROVIDER" "$CONTAINER" php -r '$p = include "/opt/dreamfactory/bootstrap/cache/packages.php"; foreach ($p as $x) { if (in_array(getenv("P"), $x["providers"] ?? [], true)) exit(0); } exit(1);'; then
  echo "[$NAME] package:discover did not register $PROVIDER" >&2
  exit 1
fi

say "migrating"
migrate_ok=1
$DOCKER exec "$CONTAINER" bash -euc '
  cd /opt/dreamfactory
  set -o pipefail
  php artisan migrate --force --no-interaction 2>&1 | grep -v "^$" | tail -n 12
' || migrate_ok=0
$DOCKER exec "$CONTAINER" bash -euc '
  cd /opt/dreamfactory
  php artisan cache:clear >/dev/null
  php artisan config:clear >/dev/null
  mkdir -p storage/framework/cache/data storage/framework/sessions storage/framework/views storage/logs bootstrap/cache
  chown -R www-data:www-data storage bootstrap/cache
'
if [[ "$migrate_ok" != 1 ]]; then
  echo "[$NAME] php artisan migrate failed (output above). Fix the cause and re-run this script." >&2
  exit 1
fi

ran="$($DOCKER exec "$CONTAINER" php /opt/dreamfactory/artisan migrate:status --no-interaction 2>/dev/null | grep -- "$MIGRATION_TAG" | grep -c 'Ran' || true)"
total="$(ls "$HERE/database/migrations" 2>/dev/null | grep -c '\.php$' || true)"
if [[ "$ran" != "$total" ]]; then
  echo "[$NAME] only $ran of $total $NAME migrations ran" >&2
  exit 1
fi
say "installed: $ran of $total $NAME migrations ran"

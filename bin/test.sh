#!/usr/bin/env bash
# Runs the df-aauth checks in a throwaway container (no network): php -l on every PHP file, then
# the PHPUnit suites.
#
#   bin/test.sh [phpunit args...]                  the DreamFactory image's PHP, e.g. --testsuite Protocol
#   PHP_IMAGE=php:8.3-cli bin/test.sh              the lowest PHP DreamFactory supports (composer: ^8.3),
#                                                  with the DreamFactory image's vendor/ mounted
#
# Environment:
#   DF_IMAGE       DreamFactory image with PHP 8.3+ (sodium, openssl) and /opt/dreamfactory/vendor
#                  (default: the 7.8.0 trial image)
#   PHP_IMAGE      run this image's PHP instead (the official php:*-cli images include sodium,
#                  openssl, curl and pdo_sqlite); DF_IMAGE then only provides vendor/
#   DF_VENDOR_DIR  host copy of /opt/dreamfactory/vendor for PHP_IMAGE (default: exported from
#                  DF_IMAGE into a temporary directory that is removed afterwards, ~250 MB)
#   PHPUNIT_PHAR   path to a PHPUnit 11 phar on the host (default: ./phpunit.phar, git-ignored;
#                  get it with: curl -sSLo phpunit.phar https://phar.phpunit.de/phpunit-11.phar)
#   LINT           0 skips the php -l pass
#   DOCKER         docker command (default: "sudo -n docker" when not root)
set -euo pipefail
PKG="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${DF_IMAGE:-registry.dreamfactory.com/dreamfactory/trial:7.8.0}"
PHAR="${PHPUNIT_PHAR:-}"
if [[ -z "$PHAR" ]]; then
  [[ -f "$PKG/phpunit.phar" ]] && PHAR="$PKG/phpunit.phar"
fi
[[ -f "${PHAR:-}" ]] || { echo "PHPUnit phar not found; set PHPUNIT_PHAR" >&2; exit 2; }
if [[ -z "${DOCKER:-}" ]]; then
  if [[ "$(id -u)" == "0" ]]; then DOCKER="docker"; else DOCKER="sudo -n docker"; fi
fi

RUN_IMAGE="$IMAGE"
MOUNTS=(-v "$PKG":/p:ro -v "$(cd "$(dirname "$PHAR")" && pwd)/$(basename "$PHAR")":/tools/phpunit.phar:ro)
if [[ -n "${PHP_IMAGE:-}" ]]; then
  RUN_IMAGE="$PHP_IMAGE"
  VENDOR="${DF_VENDOR_DIR:-}"
  if [[ -z "$VENDOR" ]]; then
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    CID="$($DOCKER create "$IMAGE")"
    $DOCKER cp "$CID:/opt/dreamfactory/vendor" - | tar -x -C "$TMP"
    $DOCKER rm "$CID" >/dev/null
    VENDOR="$TMP/vendor"
  fi
  [[ -f "$VENDOR/autoload.php" ]] || { echo "No vendor/autoload.php in $VENDOR" >&2; exit 2; }
  MOUNTS+=(-v "$VENDOR":/opt/dreamfactory/vendor:ro)
fi
# The checkout is also mounted over the image's own copy of the package: the image's optimized
# class map would otherwise load the installed df-aauth classes instead of this checkout's.
if [[ -z "${PHP_IMAGE:-}" || -d "$VENDOR/dreamfactory/df-aauth" ]]; then
  MOUNTS+=(-v "$PKG":/opt/dreamfactory/vendor/dreamfactory/df-aauth:ro)
fi

LINT_STEP='true'
if [[ "${LINT:-1}" != "0" ]]; then
  LINT_STEP='n=0; for f in $(find src tests routes config database resources bin -name "*.php"); do
      php -l "$f" >/dev/null 2>/tmp/lint.err || { cat /tmp/lint.err; n=$((n+1)); }; done
    [ "$n" -eq 0 ] || { echo "php -l: $n file(s) with errors" >&2; exit 1; }
    echo "php -l: every file OK on PHP $(php -r "echo PHP_VERSION;")"'
fi

$DOCKER run --rm --network none "${MOUNTS[@]}" -w /p --entrypoint sh "$RUN_IMAGE" \
  -c "$LINT_STEP && exec php -d memory_limit=1G /tools/phpunit.phar \"\$@\"" sh "$@"

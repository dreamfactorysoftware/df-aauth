<?php

/*
 * PHPUnit bootstrap for df-aauth.
 *
 * 1. Registers a PSR-4 autoloader for this package (DreamFactory\Core\AAuth\ => src/,
 *    DreamFactory\Core\AAuth\Tests\ => tests/). This is all the Protocol suite needs.
 * 2. Loads a Composer autoloader when one exists, for Platform tests that need Laravel / df-core:
 *    $DF_VENDOR_AUTOLOAD, ./vendor/autoload.php or /opt/dreamfactory/vendor/autoload.php (the DF image).
 *    The package autoloader stays first, so the working copy wins over any installed copy.
 */

$root = dirname(__DIR__);

spl_autoload_register(static function (string $class) use ($root): void {
    static $map = null;
    $map ??= [
        'DreamFactory\\Core\\AAuth\\Tests\\' => $root . '/tests/',
        'DreamFactory\\Core\\AAuth\\' => $root . '/src/',
    ];
    foreach ($map as $prefix => $dir) {
        if (str_starts_with($class, $prefix)) {
            $file = $dir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
            if (is_file($file)) {
                require $file;
            }
            return;
        }
    }
}, true, true);

$candidates = array_filter([
    getenv('DF_VENDOR_AUTOLOAD') ?: null,
    $root . '/vendor/autoload.php',
    '/opt/dreamfactory/vendor/autoload.php',
]);
foreach ($candidates as $file) {
    if (is_file($file)) {
        $loader = require $file;
        if ($loader instanceof \Composer\Autoload\ClassLoader) {
            $loader->addPsr4('DreamFactory\\Core\\AAuth\\', $root . '/src/', true);
            $loader->addPsr4('DreamFactory\\Core\\AAuth\\Tests\\', $root . '/tests/', true);
        }
        break;
    }
}

// The unit tests run as a Gold instance (Support\License); tests/Platform/LicenseTest.php covers the
// other license levels and the real Environment::getLicenseLevel() lookup. Guarded: the Protocol
// suite also runs without df-core.
if (class_exists(\DreamFactory\Core\Enums\LicenseLevel::class)) {
    \DreamFactory\Core\AAuth\Support\License::resolveUsing(static fn () => \DreamFactory\Core\Enums\LicenseLevel::GOLD);
}

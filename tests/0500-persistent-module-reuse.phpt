--TEST--
Two Module objects for the same path share the library record
--SKIPIF--
<?php
require_once 'require-module-load.skipif.inc';
?>
--FILE--
<?php
declare(strict_types=1);

/* Create two Module objects for the same library */
$module1 = new Pkcs11\Module(getenv('PHP11_MODULE'));
$module2 = new Pkcs11\Module(getenv('PHP11_MODULE'));

/* Both should work */
$info1 = $module1->getInfo();
$info2 = $module2->getInfo();

var_dump($info1['libraryDescription'] === $info2['libraryDescription']);

/* Destroy the first — the second must still work */
unset($module1);

$info3 = $module2->getInfo();
var_dump($info3['libraryDescription'] === $info2['libraryDescription']);

echo "OK\n";
?>
--EXPECT--
bool(true)
bool(true)
OK

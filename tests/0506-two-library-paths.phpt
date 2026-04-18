--TEST--
Per-library registry isolates independent Module objects
--SKIPIF--
<?php
require_once 'require-module-load.skipif.inc';
?>
--FILE--
<?php
declare(strict_types=1);

/* Create two Module objects — both use the same library,
 * but this tests that destroy of one doesn't affect the other */
$module1 = new Pkcs11\Module(getenv('PHP11_MODULE'));
$module2 = new Pkcs11\Module(getenv('PHP11_MODULE'));

$info1 = $module1->getInfo();
$info2 = $module2->getInfo();
var_dump($info1['libraryDescription'] === $info2['libraryDescription']);

/* Destroy first module */
unset($module1);

/* Second module must still work */
$info3 = $module2->getInfo();
var_dump($info3['libraryDescription'] === $info2['libraryDescription']);

/* Destroy second module */
unset($module2);

/* Create a new one — library should still be in registry */
$module3 = new Pkcs11\Module(getenv('PHP11_MODULE'));
$info4 = $module3->getInfo();
var_dump(isset($info4['libraryDescription']));

echo "OK\n";
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
OK

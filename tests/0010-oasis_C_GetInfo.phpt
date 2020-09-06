--TEST--
OASIS C_GetInfo() Basic test
--SKIPIF--
<?php
if (!extension_loaded('pkcs11')) {
  echo 'skip';
}

if (getenv('PHP11_MODULE') === false) {
  echo 'skip';
}
?>
--FILE--
<?php declare(strict_types=1);

$modulePath = getenv('PHP11_MODULE');
$module = new Pkcs11\Module($modulePath);

$rv = $module->C_GetInfo($info);
var_dump($rv);
var_dump(sizeof($info, COUNT_RECURSIVE));
?>
--EXPECT--
int(0)
int(8)

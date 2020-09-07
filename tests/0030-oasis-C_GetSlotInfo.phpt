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

$rv = $module->C_GetSlotList(true, $slotList);
var_dump($rv);

$rv = $module->C_GetSlotInfo($slotList[0], $slotInfo);
var_dump($rv);
var_dump(sizeof($slotInfo, COUNT_RECURSIVE));

?>
--EXPECTF--
int(0)
int(0)
int(10)

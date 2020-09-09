--TEST--
OASIS C_GetSlotList() Basic test
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
if (sizeof($slotList) > 0)
  printf("OK: %s slots".PHP_EOL, sizeof($slotList));
else
  printf("NOK: %s slots".PHP_EOL, sizeof($slotList));
?>
--EXPECTF--
int(0)
OK: %d slots

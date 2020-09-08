--TEST--
OASIS C_GetTokenInfo() Basic test
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

$rv = $module->C_GetTokenInfo($slotList[0], $tokenInfo);
var_dump($rv);
var_dump(sizeof($tokenInfo, COUNT_RECURSIVE));

?>
--EXPECTF--
int(0)
int(0)
int(21)

--TEST--
Get list of slots
--SKIPIF--
<?php

require_once 'require-module-load.skipif.inc';

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$slotList = $module->getSlotList();

if (empty($slotList)) {
    printf("NOK: %s slots".PHP_EOL, sizeof($slotList));
}

printf("OK: %s slots".PHP_EOL, sizeof($slotList));

$slotInfo = $module->getSlotInfo($slotList[0]);
var_dump($slotInfo['id'] == $slotList[0]);


$slots = $module->getSlots();
var_dump($slots);

?>
--EXPECTF--
OK: %d slots
bool(true)
array(%d) {
  [%d]=>
  array(2) {
    ["id"]=>
    int(%d)
    ["slotDescription"]=>
    string(64) "%s"
  }%A
}
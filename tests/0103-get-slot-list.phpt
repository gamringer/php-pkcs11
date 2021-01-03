--TEST--
Get list of slots
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
OK: 2 slots
bool(true)
array(2) {
  [%d]=>
  array(2) {
    ["id"]=>
    int(%d)
    ["slotDescription"]=>
    string(64) "SoftHSM slot ID 0x%x%r\s*%r"
  }
  [1]=>
  array(2) {
    ["id"]=>
    int(1)
    ["slotDescription"]=>
    string(64) "SoftHSM slot ID 0x1%r\s*%r"
  }
}
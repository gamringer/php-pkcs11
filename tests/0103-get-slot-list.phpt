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

if (sizeof($slotList) > 0)
  printf("OK: %s slots".PHP_EOL, sizeof($slotList));
else
  printf("NOK: %s slots".PHP_EOL, sizeof($slotList));

?>
--EXPECTF--
OK: %d slots

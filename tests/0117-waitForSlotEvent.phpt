--TEST--
Module::waitForSlotEvent() Basic test
--DESCRIPTION--
Please note that for most PKCS11 drivers, the blocking mode is not supported.
For these cases, the flag=CKF_DONT_BLOCK shall be used and your PHP
application shall perform a polling in order to detect the arrival or departure
of a smart card.

When SoftHSM2 is used, CKR_NO_EVENT is currently the only supported case.
--SKIPIF--
<?php

require_once 'require-module-load.skipif.inc';

$info = $module->getInfo();
if (trim($info["manufacturerID"]) == 'SoftHSM'
 && $info["libraryVersion"]["major"] == 2
 && $info["libraryVersion"]["minor"] == 2
) {
	echo 'skip: Known bug in this version of SoftHSM';
}

?>
--FILE--
<?php declare(strict_types=1);

$modulePath = getenv('PHP11_MODULE');
$module = new Pkcs11\Module($modulePath);
try {
	$slotId = $module->waitForSlotEvent(Pkcs11\CKF_DONT_BLOCK);
	var_dump(is_int($slotId) || $slotId === null);
} catch (\Pkcs11\Exception $e) {
	var_dump($e->getCode() == \Pkcs11\CKR_FUNCTION_NOT_SUPPORTED);
}

?>
--EXPECTF--
bool(true)

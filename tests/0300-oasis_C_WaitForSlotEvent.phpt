--TEST--
OASIS C_WaitForSlotEvent() Basic test
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

/* let's assume that we have at least 1 HSM into the slot 0 */
$flags = Pkcs11\CKF_DONT_BLOCK;
$r = $module->C_WaitForSlotEvent($flags, $slot);
var_dump(is_int($slot) || $slot === null);
var_dump($r);

?>
--EXPECTF--
bool(true)
int(%d)

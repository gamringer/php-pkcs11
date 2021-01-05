--TEST--
OASIS C_WaitForSlotEvent() Basic test
--DESCRIPTION--
Please note that for most PKCS11 drivers, the blocking mode is not supported.
For these cases, the flag=CKF_DONT_BLOCK shall be used and your PHP
application shall perform a polling in order to detect the arrival or departure
of a smart card.

When SoftHSM2 is used, CKR_NO_EVENT is currently the only supported case.
--XFAIL--
WIP - TODO return the $slot
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
var_dump($slotList);

/* let's assume that we have at least 1 HSM into the slot 0 */
$flags = Pkcs11\CKF_DONT_BLOCK;
$slot = $slotList[0];
$r = $module->C_WaitForSlotEvent($flags, $slot);
var_dump($slot);
var_dump($r);

?>
--EXPECTF--
XXX TODO get $slot
int(0)
array(%d) {
%A
}
int(0)
int(%d)

--TEST--
OASIS Digest Basic test - C_DigestInit(), C_Digest()
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

$rv = $module->C_GetSlotList(true, $s);
var_dump($rv);

$rv = $module->C_OpenSession($s[0], Pkcs11\CKF_SERIAL_SESSION, null, null, $session);
var_dump($rv);
var_dump($session);

$rv = $module->C_DigestInit($session,
        new Pkcs11\Mechanism(Pkcs11\CKM_SHA_1));
var_dump($rv);

$rv = $module->C_Digest($session, "BonjourHello");
//var_dump($rv);
var_dump(strlen($rv));

$rv = $module->C_DigestInit($session,
        new Pkcs11\Mechanism(Pkcs11\CKM_SHA256));
var_dump($rv);

$rv = $module->C_Digest($session, "HelloBonsoir");
//var_dump($rv);
var_dump(strlen($rv));

$rv = $module->C_CloseSession($session);
var_dump($rv);

?>
--EXPECTF--
int(0)
int(0)
object(Pkcs11\Session)#2 (2) {
  ["hSession"]=>
  int(%d)
  ["slotID"]=>
  int(%d)
}
int(0)
int(20)
int(0)
int(32)
int(0)

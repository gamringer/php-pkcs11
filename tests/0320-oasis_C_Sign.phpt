--TEST--
OASIS Sign Basic test - C_SignInit(), C_Sign()
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

$pin = getenv('PHP11_PIN');
if (strlen($pin) === 0)
  $pin = null; # Smart card without any pin code

$rv = $module->C_Login($session, Pkcs11\CKU_USER, $pin);

$Template = [
  Pkcs11\CKA_CLASS => Pkcs11\CKO_PRIVATE_KEY,
  Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_RSA,
];
$rv = $module->C_FindObjectsInit($session, $Template);
$rv = $module->C_FindObjects($session, $Objects);
if (empty($Objects)) {
  echo 'skip - Missing RSA key';
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

$pin = getenv('PHP11_PIN');
if (strlen($pin) === 0)
  $pin = null; # Smart card without any pin code

$rv = $module->C_Login($session, Pkcs11\CKU_USER, $pin);
var_dump($rv);

$Template = [
  Pkcs11\CKA_CLASS => Pkcs11\CKO_PRIVATE_KEY,
  Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_RSA,
//  Pkcs11\CKA_LABEL => 'xyz_PRIV_SIG', # the label of your private key
];

$rv = $module->C_FindObjectsInit($session, $Template);

var_dump($rv);

$rv = $module->C_FindObjects($session, $Objects);
var_dump($rv);
if (count($Objects) >= 1) {
  echo "OK, got 1 Key" . PHP_EOL;
} else {
  die("Missing private RSA key");
}

$key = $Objects[0];
var_dump($key);

$rv = $module->C_FindObjectsFinal($session);
var_dump($rv);

$rv = $module->C_SignInit($session,
        new Pkcs11\Mechanism(Pkcs11\CKM_SHA256_RSA_PKCS),
        $key);
var_dump($rv);

$rv = $module->C_Sign($session, "Cantina bar", $signature);
var_dump($rv);
var_dump(strlen($signature)); // expect 256 bytes

$rv = $module->C_Logout($session);
var_dump($rv);

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
int(0)
int(0)
OK, got 1 Key
int(%d)
int(0)
int(0)
int(0)
int(256)
int(0)
int(0)

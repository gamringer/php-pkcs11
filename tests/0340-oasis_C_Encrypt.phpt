--TEST--
OASIS Encrypt Basic test - C_EncryptInit(), C_Encrypt()
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

if (!in_array(Pkcs11\CKM_AES_CBC_PAD, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
  echo 'skip: CKM_AES_CBC_PAD not supported ';
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

$rv = $module->C_GenerateKey($session, new Pkcs11\Mechanism(Pkcs11\CKM_AES_KEY_GEN), [
  Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
  Pkcs11\CKA_VALUE_LEN => 32,
  Pkcs11\CKA_LABEL => "Test AES",
], $key);
var_dump($rv);

$iv = str_repeat(chr(0), 16);
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_AES_CBC_PAD, $iv);
$rv = $module->C_EncryptInit($session, $mechanism, $key);
var_dump($rv);

$rv = $module->C_Encrypt($session, "Hello World!", $ciphertext);
var_dump($rv);
var_dump(strlen($ciphertext)); // expect 256 bytes

$rv = $module->C_DecryptInit($session, $mechanism, $key);
var_dump($rv);

$rv = $module->C_Decrypt($session, $ciphertext, $plaintext);
var_dump($rv);
var_dump($plaintext);

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
int(0)
int(16)
int(0)
int(0)
string(12) "Hello World!"
int(0)
int(0)
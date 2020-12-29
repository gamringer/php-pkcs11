--TEST--
OASIS Session Basic test - C_OpenSession(), C_CloseSession(), C_Login(), C_Logout(), C_SessionInfo()
--SKIPIF--
<?php
if (!extension_loaded('pkcs11')) {
  echo 'skip';
}

if (getenv('PHP11_MODULE') === false) {
  echo 'skip';
}

if (getenv('PHP11_PIN') === false) {
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

$rv = $module->C_GetSessionInfo($session, $pInfo);
var_dump($rv);

if ($session->getInfo() !== $pInfo) {
  printf("Error getInfo() vs C_GetSessionInfo()".PHP_EOL);
  print_r($session->getInfo());
  print_r($pInfo);
}

$pin = getenv('PHP11_PIN');
if (strlen($pin) === 0)
  $pin = null; # Smart card without any pin code

$rv = $module->C_Login($session, Pkcs11\CKU_USER, $pin);
var_dump($rv);

$rv = $module->C_Logout($session);
var_dump($rv);

$rv = $module->C_CloseSession($session);
// or use unset($session); # aka C_CloseSession()

printf("OK".PHP_EOL);

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
OK

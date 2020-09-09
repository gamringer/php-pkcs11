--TEST--
OASIS Session Basic test - C_Login(), C_Logout(), C_SessionInfo()
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

$session = new Pkcs11\Session($module, $s[0], Pkcs11\CKF_SERIAL_SESSION); # aka C_OpenSession()

$pin = getenv('PHP11_PIN');
if (strlen($pin) === 0)
  $pin = null; # Smart card without any pin code

$rv = $session->C_Login(Pkcs11\CKU_USER, $pin);
var_dump($rv);

$rv = $session->C_Logout();
var_dump($rv);

unset($session); # aka C_CloseSession()

printf("OK".PHP_EOL);

?>
--EXPECTF--
int(0)
int(0)
int(0)
OK

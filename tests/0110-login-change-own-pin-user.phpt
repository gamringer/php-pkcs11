--TEST--
Change own PIN as User
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

?>
--FILE--
<?php

declare(strict_types=1);

$newPin = '654321';


$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);

try {
	$session->login(Pkcs11\CKU_USER, $newPin);
	echo 'New PIN Login succeeded' . PHP_EOL;
} catch (\Throwable $e) {
	echo 'New PIN Login failed' . PHP_EOL;
}
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));
$session->setPin(getenv('PHP11_PIN'), $newPin);
echo 'PIN changed' . PHP_EOL;
$session->logout();

try {
	$session->login(Pkcs11\CKU_USER, $newPin);
	echo 'New PIN Login succeeded' . PHP_EOL;
} catch (\Throwable $e) {
	echo 'New PIN Login failed' . PHP_EOL;
}

$session->setPin($newPin, getenv('PHP11_PIN'));
echo 'PIN changed back' . PHP_EOL;
$session->logout();

?>
--EXPECTF--
New PIN Login failed
PIN changed
New PIN Login succeeded
PIN changed back
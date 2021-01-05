--TEST--
Change own PIN as User
--DESCRIPTION--
This test scenario detects that a wrong PIN is used, then it
sets the proper PIN to PHP11_PIN once again.
--SKIPIF--
<?php

if (!extension_loaded('pkcs11')) {
    echo 'skip';
}

if (getenv('PHP11_MODULE') === false) {
    echo 'skip';
}

if (getenv('PHP11_SLOT') === false) {
    echo 'skip';
}

if (getenv('PHP11_PIN') === false) {
    echo 'skip';
}

try {
    $module = new Pkcs11\Module(getenv('PHP11_MODULE'));
    $session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
	$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));
	$session->logout();
} catch (\Throwable $e) {
    echo 'skip';
}

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$tokenInfo = $module->getTokenInfo((int)getenv('PHP11_SLOT'));
$newPin = str_repeat('0', $tokenInfo['ulMaxPinLen']);

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

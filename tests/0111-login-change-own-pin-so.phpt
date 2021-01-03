--TEST--
Change own PIN as SO
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

if (getenv('PHP11_SOPIN') === false) {
    echo 'skip';
}

try {
    $module = new Pkcs11\Module(getenv('PHP11_MODULE'));
    $session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
	$session->login(Pkcs11\CKU_SO, getenv('PHP11_SOPIN'));
	$session->logout();
} catch (\Throwable $e) {
    echo 'skip';
}

?>
--FILE--
<?php

declare(strict_types=1);

$newSoPin = '87654321';


$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);

try {
	$session->login(Pkcs11\CKU_SO, $newSoPin);
	echo 'New SOPIN Login succeeded' . PHP_EOL;
} catch (\Throwable $e) {
	echo 'New SOPIN Login failed' . PHP_EOL;
}
$session->login(Pkcs11\CKU_SO, getenv('PHP11_SOPIN'));
$session->setPin(getenv('PHP11_SOPIN'), $newSoPin);
echo 'SOPIN changed' . PHP_EOL;
$session->logout();

try {
	$session->login(Pkcs11\CKU_SO, $newSoPin);
	echo 'New SOPIN Login succeeded' . PHP_EOL;
} catch (\Throwable $e) {
	echo 'New SOPIN Login failed' . PHP_EOL;
}

$session->setPin($newSoPin, getenv('PHP11_SOPIN'));
echo 'SOPIN changed back' . PHP_EOL;
$session->logout();

?>
--EXPECTF--
New SOPIN Login failed
SOPIN changed
New SOPIN Login succeeded
SOPIN changed back
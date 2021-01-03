--TEST--
Login as User
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
} catch (\Throwable $e) {
    echo 'skip';
}

?>
--FILE--
<?php

declare(strict_types=1);


$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));
var_dump($session->getInfo()['state']);
$session->logout();
var_dump($session->getInfo()['state']);

?>
--EXPECTF--
int(3)
int(2)

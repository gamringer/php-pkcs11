--TEST--
Login as SO
--SKIPIF--
<?php

require_once 'require-open-session.skipif.inc';

if (getenv('PHP11_SOPIN') === false) {
    echo 'skip';
}

?>
--FILE--
<?php

declare(strict_types=1);


$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_SO, getenv('PHP11_SOPIN'));
var_dump($session->getInfo()['state']);
$session->logout();
var_dump($session->getInfo()['state']);

?>
--EXPECTF--
int(4)
int(2)
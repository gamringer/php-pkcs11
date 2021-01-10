--TEST--
Digesting using SHA1
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

if (!in_array(Pkcs11\CKM_SHA_1, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
	echo 'skip: CKM_SHA_1 not supported ';
}

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$data = "Hello World!";
$digest = $session->digest(new Pkcs11\Mechanism(Pkcs11\CKM_SHA_1), $data);
var_dump(bin2hex($digest));

$session->logout();

?>
--EXPECTF--
string(40) "2ef7bde608ce5404e97d5f042f95f89f1c232871"

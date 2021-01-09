--TEST--
Encrypt/Decrypt using AES-CBC
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

if (!in_array(Pkcs11\CKM_SHA256, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
	echo 'skip: CKM_SHA256 not supported ';
}

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$object = $session->createObject([
	Pkcs11\CKA_CLASS => Pkcs11\CKO_DATA,
	Pkcs11\CKA_VALUE => 'Hello World!',
]);

$digestContext = $session->initializeDigest(new Pkcs11\Mechanism(Pkcs11\CKM_SHA256));

$digestContext->update("Hello W");
$digestContext->update("orld!");
$digestContext->keyUpdate($object);
$digest = $digestContext->finalize();
var_dump(bin2hex($digest));

$session->logout();

?>
--EXPECTF--
string(64) "95a5a79bf6218dd0938950acb61bca24d5809172fe6cfd7f1af4b059449e52f8"

--TEST--
Digesting using SHA256 with updates
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

$key = $session->createObject([
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_GENERIC_SECRET,
	Pkcs11\CKA_VALUE => str_repeat(chr(0), 32),
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SIGN => true,
	Pkcs11\CKA_EXTRACTABLE => true,
]);

$digestContext = $session->initializeDigest(new Pkcs11\Mechanism(Pkcs11\CKM_SHA256));

$digestContext->update("Hello W");
$digestContext->update("orld!");
$digestContext->keyUpdate($key);
$digest = $digestContext->finalize();
var_dump(bin2hex($digest));

$session->logout();

?>
--EXPECTF--
string(64) "6c84389e0d1a52d520f032f99715907259f1e8dc47db3a0b3d57931c3c68abca"

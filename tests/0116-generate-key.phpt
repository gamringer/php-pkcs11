--TEST--
Generate generic key
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$key = $session->generateKey(new Pkcs11\Mechanism(Pkcs11\CKM_GENERIC_SECRET_KEY_GEN), [
	Pkcs11\CKA_VALUE_LEN => 32,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_GENERIC_SECRET,
	Pkcs11\CKA_LABEL => "Test Generic Key",
]);

try {
	$attributes = $key->getAttributeValue([
		Pkcs11\CKA_VALUE,
		Pkcs11\CKA_LABEL,
	]);
	var_dump($attributes);
} catch (\Throwable $e) {
	echo $e->getMessage();
}

$session->logout();

?>
--EXPECTF--
(0x00000011/CKR_ATTRIBUTE_SENSITIVE) PKCS#11 module error: Unable to get attribute value
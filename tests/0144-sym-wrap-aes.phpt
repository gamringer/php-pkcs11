--TEST--
Wraping using AES-KEY-WRAP
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

if (!in_array(Pkcs11\CKM_AES_KEY_WRAP, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
	echo 'skip: CKM_AES_KEY_WRAP not supported ';
}

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));


$key = $session->generateKey(new Pkcs11\Mechanism(Pkcs11\CKM_AES_KEY_GEN), [
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_DECRYPT => true,
	Pkcs11\CKA_VALUE_LEN => 32,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_AES,
	Pkcs11\CKA_LABEL => "Test AES",
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_EXTRACTABLE => true,
]);

$wkey = $session->generateKey(new Pkcs11\Mechanism(Pkcs11\CKM_AES_KEY_GEN), [
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_DECRYPT => true,
	Pkcs11\CKA_WRAP => true,
	Pkcs11\CKA_UNWRAP => true,
	Pkcs11\CKA_VALUE_LEN => 32,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_AES,
	Pkcs11\CKA_LABEL => "Test Wrapping AES",
	Pkcs11\CKA_PRIVATE => true,
]);

$ciphertext = $wkey->wrap(new Pkcs11\Mechanism(Pkcs11\CKM_AES_KEY_WRAP), $key);
var_dump(bin2hex($ciphertext));

$session->logout();

?>
--EXPECTF--
string(80) "%x"

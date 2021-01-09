--TEST--
HMAC using SHA-256
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

if (!in_array(Pkcs11\CKM_SHA256_HMAC, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
	echo 'skip: CKM_SHA256_HMAC not supported ';
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
]);

$data = "Hello World!";
$mac = $key->sign(new Pkcs11\Mechanism(Pkcs11\CKM_SHA256_HMAC), $data);
var_dump(bin2hex($mac));

$session->logout();

?>
--EXPECTF--
string(64) "%x"
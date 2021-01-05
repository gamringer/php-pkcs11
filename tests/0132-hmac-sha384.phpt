--TEST--
Generate generic key
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

if (!in_array(Pkcs11\CKM_SHA384_HMAC, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
	echo 'skip: CKM_SHA384_HMAC not supported ';
}

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$key = $session->generateKey(new Pkcs11\Mechanism(Pkcs11\CKM_GENERIC_SECRET_KEY_GEN), [
	Pkcs11\CKA_VALUE_LEN => 48,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_GENERIC_SECRET,
	Pkcs11\CKA_LABEL => "Test Generic Key",
]);

$data = "Hello World!";
$mac = $key->sign(new Pkcs11\Mechanism(Pkcs11\CKM_SHA384_HMAC), $data);
var_dump(bin2hex($mac));

$session->logout();

?>
--EXPECTF--
string(96) "%x"
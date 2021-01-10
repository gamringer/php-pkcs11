--TEST--
Sign/Verify using RSA PKCS1v1.5
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

if (!in_array(Pkcs11\CKM_SHA256_RSA_PKCS, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
	echo 'skip: CKM_SHA256_RSA_PKCS not supported ';
}

require_once 'require-generate-key-pair.skipif.inc';

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$keypair = $session->generateKeyPair(new Pkcs11\Mechanism(Pkcs11\CKM_RSA_PKCS_KEY_PAIR_GEN), [
	Pkcs11\CKA_VERIFY => true,
	Pkcs11\CKA_MODULUS_BITS => 2048,
	Pkcs11\CKA_PUBLIC_EXPONENT => hex2bin('010001'),
	Pkcs11\CKA_LABEL => "Test RSA Public",
],[
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_SIGN => true,
	Pkcs11\CKA_LABEL => "Test RSA Private",
]);

$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_SHA256_RSA_PKCS);

$data = "Hello World!";
$signature = $keypair->skey->sign($mechanism, $data);
var_dump(bin2hex($signature));
$valid = $keypair->pkey->verify($mechanism, $data, $signature);
var_dump($valid);

$session->logout();

?>
--EXPECTF--
string(512) "%x"
bool(true)

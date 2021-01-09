--TEST--
Encrypt/Decrypt using RSA PKCS1v1.5
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

if (!in_array(Pkcs11\CKM_RSA_PKCS, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
	echo 'skip: CKM_RSA_PKCS not supported ';
}

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$keypair = $session->generateKeyPair(new Pkcs11\Mechanism(Pkcs11\CKM_RSA_PKCS_KEY_PAIR_GEN), [
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_MODULUS_BITS => 2048,
	Pkcs11\CKA_PUBLIC_EXPONENT => hex2bin('010001'),
	Pkcs11\CKA_LABEL => "Test RSA Encrypt Public",
],[
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_DECRYPT => true,
	Pkcs11\CKA_LABEL => "Test RSA Encrypt Private",
]);

$data = "Hello World!";
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_RSA_PKCS);
$ciphertext = $keypair->pkey->encrypt($mechanism, $data);
var_dump(bin2hex($ciphertext));

$plaintext = $keypair->skey->decrypt($mechanism, $ciphertext);
var_dump($plaintext);

$session->logout();

?>
--EXPECTF--
string(512) "%x"
string(12) "Hello World!"

--TEST--
Encrypt/Decrypt using AES-CBC
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

if (!in_array(Pkcs11\CKM_AES_CBC_PAD, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
	echo 'skip: CKM_AES_CBC_PAD not supported ';
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
	Pkcs11\CKA_VALUE_LEN => 32,
	Pkcs11\CKA_LABEL => "Test AES",
]);

$iv = random_bytes(16);
$data = 'Hello World!';
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_AES_CBC_PAD, $iv);
$ciphertext = $key->encrypt($mechanism, $data);
var_dump(bin2hex($ciphertext));

$plaintext = $key->decrypt($mechanism, $ciphertext);
var_dump($plaintext);

$session->logout();

?>
--EXPECTF--
string(32) "%x"
string(12) "Hello World!"
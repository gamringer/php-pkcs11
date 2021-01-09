--TEST--
Encrypt/Decrypt using Chacha20-Poly1305
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

if (!in_array(Pkcs11\CKM_CHACHA20_POLY1305, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
	echo 'skip: CKM_CHACHA20_POLY1305 not supported ';
}

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));


$key = $session->generateKey(new Pkcs11\Mechanism(Pkcs11\CKM_CHACHA20_KEY_GEN), [
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_VALUE_LEN => 32,
	Pkcs11\CKA_LABEL => "Test Chacha20",
]);

$nonce = random_bytes(24);
$aad = '';
$data = 'Hello World!';
$cs20pParams = new Pkcs11\Salsa20Chacha20Poly1305Params($nonce, $aad);
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_CHACHA20_POLY1305, $cs20pParams);

$ciphertext = $key->encrypt($mechanism, $data);
var_dump(bin2hex($ciphertext));

$plaintext = $key->decrypt($mechanism, $ciphertext);
var_dump($plaintext);

$session->logout();

?>
--EXPECTF--
string(%d) "%x"
string(12) "Hello World!"
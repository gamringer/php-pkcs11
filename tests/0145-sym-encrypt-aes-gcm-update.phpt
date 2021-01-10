--TEST--
Encrypt/Decrypt using AES-GCM with update
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

if (!in_array(Pkcs11\CKM_AES_GCM, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
	echo 'skip: CKM_AES_GCM not supported ';
}

require_once 'require-create-object.skipif.inc';

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$key = $session->createObject([
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_AES,
	Pkcs11\CKA_VALUE => str_repeat(chr(0), 32),
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SIGN => true,
]);

$iv = str_repeat('0', 16);
$aad = '';
$gcmParams = new Pkcs11\GcmParams($iv, $aad, 128);
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_AES_GCM, $gcmParams);

$encryptionContext = $key->initializeEncryption($mechanism);

$ciphertext = '';
$ciphertext .= $encryptionContext->update(str_repeat('0', 16));
var_dump(bin2hex($ciphertext));
$ciphertext .= $encryptionContext->update(str_repeat('1', 16));
var_dump(bin2hex($ciphertext));
$ciphertext .= $encryptionContext->finalize();
var_dump(bin2hex($ciphertext));

$decryptionContext = $key->initializeDecryption($mechanism);

$plaintext = '';
$plaintext .= $decryptionContext->update(substr($ciphertext, 0, 18));
var_dump(bin2hex($plaintext));
$plaintext .= $decryptionContext->update(substr($ciphertext, 18));
var_dump(bin2hex($plaintext));
$plaintext .= $decryptionContext->finalize();
var_dump(bin2hex($plaintext));


$session->logout();

?>
--EXPECTF--
string(32) "83541da26b31a09d92c1fe7994c545e0"
string(64) "83541da26b31a09d92c1fe7994c545e020f6bf42face8af788a4dc6157fca675"
string(96) "83541da26b31a09d92c1fe7994c545e020f6bf42face8af788a4dc6157fca675daf8d4b5731df66c12b2b806a64daa25"
string(0) ""
string(0) ""
string(64) "3030303030303030303030303030303031313131313131313131313131313131"

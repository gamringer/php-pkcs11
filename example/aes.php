<?php

declare(strict_types=1);

$module = new Pkcs11\Module('/usr/lib/softhsm/libsofthsm2.so');
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], PKCS11\CKF_RW_SESSION);
$session->login(PKCS11\CKU_USER,'123456');

$key = $session->generateKey(PKCS11\CKM_AES_KEY_GEN, [
	PKCS11\CKA_CLASS => PKCS11\CKO_SECRET_KEY,
	PKCS11\CKA_TOKEN => true,
	PKCS11\CKA_SENSITIVE => true,
	PKCS11\CKA_VALUE_LEN => 32,
	PKCS11\CKA_KEY_TYPE => PKCS11\CKK_AES,
	PKCS11\CKA_LABEL => "Test AES",
	PKCS11\CKA_PRIVATE => true,
]);

$iv = random_bytes(16);
$data = 'Hello World!';
$ciphertext = $key->encrypt(PKCS11\CKM_AES_CBC_PAD, $data, $iv);
var_dump(bin2hex($ciphertext));

$plaintext = $key->decrypt(PKCS11\CKM_AES_CBC_PAD, $ciphertext, $iv);
var_dump($plaintext);

$session->logout();

<?php

declare(strict_types=1);

$module = new Pkcs11\Module('/usr/lib/softhsm/libsofthsm2.so');
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER,'123456');

$key = $session->generateKey(Pkcs11\CKM_AES_KEY_GEN, [
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_TOKEN => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_VALUE_LEN => 32,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_AES,
	Pkcs11\CKA_LABEL => "Test AES",
	Pkcs11\CKA_PRIVATE => true,
]);

$iv = random_bytes(16);
$data = 'Hello World!';
$ciphertext = $key->encrypt(Pkcs11\CKM_AES_CBC_PAD, $data, $iv);
var_dump(bin2hex($ciphertext));

$plaintext = $key->decrypt(Pkcs11\CKM_AES_CBC_PAD, $ciphertext, $iv);
var_dump($plaintext);

$session->logout();

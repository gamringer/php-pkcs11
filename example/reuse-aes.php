<?php

declare(strict_types=1);

$module = new Pkcs11\Module('/usr/lib/softhsm/libsofthsm2.so');
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], PKCS11\CKF_RW_SESSION);
$session->login(PKCS11\CKU_USER,'123456');

$keys = $session->findObjects([
	PKCS11\CKA_LABEL => "Test AES",
]);

$iv = random_bytes(16);
$data = 'Hello World!';
$ciphertext = $keys[0]->encrypt(PKCS11\CKM_AES_CBC_PAD, $data, $iv);
var_dump(bin2hex($ciphertext));

$plaintext = $keys[0]->decrypt(PKCS11\CKM_AES_CBC_PAD, $ciphertext, $iv);
var_dump($plaintext);

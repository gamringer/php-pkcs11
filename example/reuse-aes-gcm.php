<?php

declare(strict_types=1);

$module = new Pkcs11\Module('/usr/local/lib/softhsm/libsofthsm2.so');
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER,'123456');

$keys = $session->findObjects([
	Pkcs11\CKA_LABEL => "Test AES",
]);

$iv = random_bytes(16);
$aad = '';
$gcmParams = new Pkcs11\GcmParams($iv, $aad, 128);

$data = 'Hello World!';
var_dump($data);
$ciphertext = $keys[0]->encrypt(Pkcs11\CKM_AES_GCM, $data, $gcmParams);
var_dump($data);
var_dump(bin2hex($ciphertext));

$plaintext = $keys[0]->decrypt(Pkcs11\CKM_AES_GCM, $ciphertext, $gcmParams);
var_dump($plaintext);

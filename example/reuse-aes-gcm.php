<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module($modulePath);
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
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_AES_GCM, $gcmParams);
$ciphertext = $keys[0]->encrypt($mechanism, $data);
var_dump(bin2hex($ciphertext));

$plaintext = $keys[0]->decrypt($mechanism, $ciphertext);
var_dump($plaintext);

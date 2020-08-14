<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module($modulePath);
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER,'123456');

$keypair = $session->generateKeyPair(Pkcs11\CKM_RSA_PKCS_KEY_PAIR_GEN, [
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_MODULUS_BITS => 2048,
	Pkcs11\CKA_PUBLIC_EXPONENT => hex2bin('010001'),
],[
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_DECRYPT => true,
]);

$oaepParam = new Pkcs11\RsaOaepParams(Pkcs11\CKM_SHA_1, Pkcs11\CKG_MGF1_SHA1);

$encryptionContext = $keypair->pkey->initializeEncryption(Pkcs11\CKM_RSA_PKCS_OAEP, $oaepParam);

$ciphertext = '';
$ciphertext .= $encryptionContext->update(random_bytes(16));
var_dump(bin2hex($ciphertext));
$ciphertext .= $encryptionContext->update(random_bytes(16));
var_dump(bin2hex($ciphertext));
$ciphertext .= $encryptionContext->finalize();
var_dump(bin2hex($ciphertext));

var_dump($encryptionContext);

$session->logout();

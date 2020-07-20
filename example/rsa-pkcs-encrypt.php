<?php

declare(strict_types=1);

require 'helper.php';

use phpseclib\Crypt\RSA;

$module = new Pkcs11\Module($modulePath);
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER,'123456');

$keypair = $session->generateKeyPair(Pkcs11\CKM_RSA_PKCS_KEY_PAIR_GEN, [
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_MODULUS_BITS => 2048,
	Pkcs11\CKA_PUBLIC_EXPONENT => hex2bin('010001'),
	Pkcs11\CKA_LABEL => "Test RSA Encrypt Public",
],[
	Pkcs11\CKA_TOKEN => true,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_DECRYPT => true,
	Pkcs11\CKA_LABEL => "Test RSA Encrypt Private",
]);

$data = "Hello World!";
$ciphertext = $keypair->pkey->encrypt(Pkcs11\CKM_RSA_PKCS, $data);
var_dump($ciphertext);

$plaintext = $keypair->skey->decrypt(Pkcs11\CKM_RSA_PKCS, $ciphertext);
var_dump($plaintext);

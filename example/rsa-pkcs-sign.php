<?php

declare(strict_types=1);

$module = new Pkcs11\Module('/usr/lib/softhsm/libsofthsm2.so');
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], PKCS11\CKF_RW_SESSION);
$session->login(PKCS11\CKU_USER,'123456');

$keypair = $session->generateKeyPair(PKCS11\CKM_RSA_PKCS_KEY_PAIR_GEN, [
	PKCS11\CKA_VERIFY => true,
	PKCS11\CKA_MODULUS_BITS => 2048,
	PKCS11\CKA_PUBLIC_EXPONENT => hex2bin('010001'),
],[
	PKCS11\CKA_TOKEN => true,
	PKCS11\CKA_PRIVATE => true,
	PKCS11\CKA_SENSITIVE => true,
	PKCS11\CKA_SIGN => true,
]);

$data = "Hello World!";
$signature = $keypair->pkey->sign(PKCS11\CKM_RSA_PKCS, $data);

var_dump(bin2hex($signature));

$session->logout();

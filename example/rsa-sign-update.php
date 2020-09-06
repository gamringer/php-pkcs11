<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module($modulePath);
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, $pinCode);

$keypair = $session->generateKeyPair(new Pkcs11\Mechanism(Pkcs11\CKM_RSA_PKCS_KEY_PAIR_GEN), [
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_MODULUS_BITS => 2048,
	Pkcs11\CKA_PUBLIC_EXPONENT => hex2bin('010001'),
],[
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_DECRYPT => true,
]);

$pssParams = new Pkcs11\RsaPssParams(Pkcs11\CKM_SHA256, Pkcs11\CKG_MGF1_SHA256, 32);
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_SHA256_RSA_PKCS_PSS, $pssParams);

$signatureContext = $keypair->skey->initializeSignature($mechanism);

$signatureContext->update('Hello Wo');
$signatureContext->update('rld!');
$signature = $signatureContext->finalize();

var_dump($signatureContext);
var_dump(bin2hex($signature));

$verificationContext = $keypair->pkey->initializeVerification($mechanism);

$verificationContext->update('Hello Wo');
$verificationContext->update('rld!');
$verifies = $verificationContext->finalize($signature);

var_dump($verificationContext);
var_dump($verifies);

$session->logout();

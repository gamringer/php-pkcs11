<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module($modulePath);
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER,'123456');

$domainParameters = hex2bin('06032B656F'); // X448
$rawPublickeyOther = hex2bin('04383c9308d2077a0872082fcbe16aeb4bc10d6fcf24036869c20e15bf36935cf4d7f221eb308c7a9aea833fb18de7d95b61e2c6329da407e5c2');

$domainParameters = hex2bin('06032B656E'); // X25519
$rawPublickeyOther = hex2bin('0420715bbc7a82f99613f23580cdf87e0ff179524201fdad7d7d389529e6cb0ad25c');


// SoftHSMv2 uses CKM_EC_EDWARDS_KEY_PAIR_GEN instead of CKM_EC_MONTGOMERY_KEY_PAIR_GEN
$keypair = $session->generateKeyPair(new Pkcs11\Mechanism(Pkcs11\CKM_EC_EDWARDS_KEY_PAIR_GEN), [
	Pkcs11\CKA_LABEL => "Test X25519 Public",
	Pkcs11\CKA_EC_PARAMS => $domainParameters,
],[
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_DERIVE => true,
	Pkcs11\CKA_LABEL => "Test X25519 Private",
]);

var_dump(bin2hex($keypair->pkey->getAttributeValue([
	Pkcs11\CKA_EC_POINT,
])[Pkcs11\CKA_EC_POINT]));

$shared = '';

// SoftHSM2 only supports CKD_NULL
$params = new Pkcs11\Ecdh1DeriveParams(Pkcs11\CKD_NULL, $shared, $rawPublickeyOther);
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_ECDH1_DERIVE, $params);
$secret = $keypair->skey->derive($mechanism, [
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_AES,
	Pkcs11\CKA_SENSITIVE => false,
	Pkcs11\CKA_EXTRACTABLE => true,
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_DECRYPT => true,
]);

var_dump(bin2hex($secret->getAttributeValue([
	Pkcs11\CKA_VALUE,
])[Pkcs11\CKA_VALUE]));

var_dump($secret);

$iv = random_bytes(16);
$data = 'Hello World!';
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_AES_CBC_PAD, $iv);
$ciphertext = $secret->encrypt($mechanism, $data);
var_dump(bin2hex($ciphertext));

$session->logout();
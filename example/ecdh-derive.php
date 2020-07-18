<?php

declare(strict_types=1);

use Mdanter\Ecc\Crypto\Signature\SignHasher;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;

require 'helper.php';

$module = new Pkcs11\Module('/usr/local/lib/softhsm/libsofthsm2.so');
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER,'123456');

$domainParameters = hex2bin('06082A8648CE3D030107');

$keypair = $session->generateKeyPair(Pkcs11\CKM_EC_KEY_PAIR_GEN, [
	Pkcs11\CKA_LABEL => "Test ECDH Public",
	Pkcs11\CKA_EC_PARAMS => $domainParameters,
],[
	Pkcs11\CKA_TOKEN => true,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_DERIVE => true,
	Pkcs11\CKA_LABEL => "Test ECDH Private",
]);

$rawPublickeyOther = hex2bin('04410434ffa340f38c53f79c02361028ab63d4430e734f6bc42d2c59ae18e980881eb1d7efad542fa2273c9860fe4bac68ef317165f1c7f0dbc6db1b803be65c735705');

$shared = '';

// SoftHSM2 only supports CKD_NULL
$params = new Pkcs11\Ecdh1DeriveParams(Pkcs11\CKD_NULL, $shared, $rawPublickeyOther);
$secret = $keypair->skey->derive(Pkcs11\CKM_ECDH1_DERIVE, $params, [
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_AES,
	Pkcs11\CKA_SENSITIVE => false,
	Pkcs11\CKA_EXTRACTABLE => false,
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_DECRYPT => true,
]);

var_dump($secret);

$iv = random_bytes(16);
$data = 'Hello World!';
$ciphertext = $secret->encrypt(Pkcs11\CKM_AES_CBC_PAD, $data, $iv);
var_dump(bin2hex($ciphertext));

$session->logout();

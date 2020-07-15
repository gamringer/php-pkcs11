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

$attributes = $keypair->pkey->getAttributeValue([
	Pkcs11\CKA_LABEL,
	Pkcs11\CKA_EC_POINT,
]);

$shared = 'allo';
$public = '';
$params = new Pkcs11\Ecdh1DeriveParams(Pkcs11\CKD_SHA256_KDF, $shared, $public);
$secret = $keypair->skey->derive(Pkcs11\CKM_ECDH1_DERIVE, $params);

var_dump($secret);

$session->logout();

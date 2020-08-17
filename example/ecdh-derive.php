<?php

declare(strict_types=1);

use Mdanter\Ecc\Crypto\Signature\SignHasher;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;

require 'helper.php';

$module = new Pkcs11\Module($modulePath);
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER,'123456');

// P-256
$domainParameters = hex2bin('06082A8648CE3D030107');
$rawPublickeyOther = hex2bin('04410434ffa340f38c53f79c02361028ab63d4430e734f6bc42d2c59ae18e980881eb1d7efad542fa2273c9860fe4bac68ef317165f1c7f0dbc6db1b803be65c735705');

// P-384
$domainParameters = hex2bin('06052B81040022');
$rawPublickeyOther = hex2bin('049f0a09e8a6fc87f4804642c782b2cd3e566b3e62262090d94e12933a00916f559b62ea33197706a302f0722b781a9349ea8f0f2bcea854cdcf5d9ff0e0a19c3c35d63578292307d1d83031c0134700c2990ed5b38f6c92245103c2c1352132a3');

// P-521
$domainParameters = hex2bin('06052B81040023');
$rawPublickeyOther = hex2bin('04016384cfbeb6144213dc7d563b52db9ecc6450f87e94df25c8568f8e24674ad91f2bc81476bc21f4ae4106435d28a9cc6b846cb6922819ba57d04e928b1da3cacb470000df9bbda40822c5a744213d06d85d572b6f8a224c13b2ce954a31199b578551cb3c2f8567b17c7b6cea1a0aea45a9a79cc14db82ec39fa0fb653fed5601ac3a16');

$keypair = $session->generateKeyPair(new Pkcs11\Mechanism(Pkcs11\CKM_EC_KEY_PAIR_GEN), [
	Pkcs11\CKA_LABEL => "Test ECDH Public",
	Pkcs11\CKA_EC_PARAMS => $domainParameters,
],[
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_DERIVE => true,
	Pkcs11\CKA_LABEL => "Test ECDH Private",
]);

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
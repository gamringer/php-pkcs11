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
	Pkcs11\CKA_VERIFY => true,
	Pkcs11\CKA_LABEL => "Test ECDSA Public",
	Pkcs11\CKA_EC_PARAMS => $domainParameters,
],[
	Pkcs11\CKA_TOKEN => true,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_SIGN => true,
	Pkcs11\CKA_LABEL => "Test ECDSA Private",
]);

$attributes = $keypair->pkey->getAttributeValue([
	Pkcs11\CKA_LABEL,
	Pkcs11\CKA_EC_POINT,
]);

$der = pubKeyToDer(substr($attributes[Pkcs11\CKA_EC_POINT], 2));
$der = pubKeyToDerBK($attributes[Pkcs11\CKA_EC_POINT]);

$data = "Hello World!";
$hash = hash('sha256', $data, true);
$signature = $keypair->skey->sign(Pkcs11\CKM_ECDSA, $hash);
$check = $keypair->pkey->verify(Pkcs11\CKM_ECDSA, $hash, $signature);

$session->logout();

echo "Data:\n" . bin2hex($data), PHP_EOL, PHP_EOL;
echo "Signature:\n" . bin2hex($signature), PHP_EOL, PHP_EOL;
echo "R:\n" . bin2hex(substr($signature,  0, 32)), PHP_EOL, PHP_EOL;
echo "S:\n" . bin2hex(substr($signature, 32, 32)), PHP_EOL, PHP_EOL;
echo 'Validates: ' . ($check ? 'Yes' : 'No'), PHP_EOL, PHP_EOL;

echo "B64 Signature:\n" . base64url_encode($signature), PHP_EOL, PHP_EOL;
echo $pem, PHP_EOL;

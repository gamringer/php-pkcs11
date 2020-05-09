<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module('/usr/lib/softhsm/libsofthsm2.so');
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER,'123456');

$keypair = $session->generateKeyPair(Pkcs11\CKM_RSA_PKCS_KEY_PAIR_GEN, [
	Pkcs11\CKA_VERIFY => true,
	Pkcs11\CKA_MODULUS_BITS => 2048,
	Pkcs11\CKA_PUBLIC_EXPONENT => hex2bin('010001'),
	Pkcs11\CKA_LABEL => "Test RSA Public",
],[
	Pkcs11\CKA_TOKEN => true,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_SIGN => true,
	Pkcs11\CKA_LABEL => "Test RSA Private",
]);

$data = "Hello World!";
$signature = $keypair->skey->sign(Pkcs11\CKM_SHA256_RSA_PKCS, $data);

$attributes = $keypair->skey->getAttributeValue([
	Pkcs11\CKA_PUBLIC_EXPONENT,
	Pkcs11\CKA_MODULUS,
]);

$session->logout();

$pem = rawToRsaPem($attributes[Pkcs11\CKA_MODULUS], $attributes[Pkcs11\CKA_PUBLIC_EXPONENT]);
$r = openssl_verify($data, $signature, $pem, OPENSSL_ALGO_SHA256 );

echo "Data:\n" . bin2hex($data), PHP_EOL, PHP_EOL;
echo "Signature:\n" . bin2hex($signature), PHP_EOL, PHP_EOL;
echo "Public Exponent:\n" . bin2hex($attributes[Pkcs11\CKA_PUBLIC_EXPONENT]), PHP_EOL, PHP_EOL;
echo "Modulus:\n" . bin2hex($attributes[Pkcs11\CKA_MODULUS]), PHP_EOL, PHP_EOL;
echo 'Validates: ' . ($r ? 'Yes' : 'No'), PHP_EOL, PHP_EOL;


<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module($modulePath);
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER,'123456');

$keys = $session->findObjects([
	Pkcs11\CKA_LABEL => "Test RSA Private",
]);

$attributes = $keys[0]->getAttributeValue([
	Pkcs11\CKA_PUBLIC_EXPONENT,
	Pkcs11\CKA_MODULUS,
]);

$data = "Hello World!";
$signature = $keys[0]->sign(new Pkcs11\Mechanism(Pkcs11\CKM_SHA256_RSA_PKCS), $data);

$session->logout();

$pem = rawToRsaPem($attributes[Pkcs11\CKA_MODULUS], $attributes[Pkcs11\CKA_PUBLIC_EXPONENT]);
$r = openssl_verify($data, $signature, $pem, OPENSSL_ALGO_SHA256);

echo "Data:\n" . bin2hex($data), PHP_EOL, PHP_EOL;
echo "Signature:\n" . bin2hex($signature), PHP_EOL, PHP_EOL;
echo "Public Exponent:\n" . bin2hex($attributes[Pkcs11\CKA_PUBLIC_EXPONENT]), PHP_EOL, PHP_EOL;
echo "Modulus:\n" . bin2hex($attributes[Pkcs11\CKA_MODULUS]), PHP_EOL, PHP_EOL;
echo 'Validates: ' . ($r ? 'Yes' : 'No'), PHP_EOL, PHP_EOL;

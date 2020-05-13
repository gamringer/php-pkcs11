<?php

declare(strict_types=1);

require 'helper.php';

use phpseclib\Crypt\RSA;

$module = new Pkcs11\Module('/usr/lib/softhsm/libsofthsm2.so');
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
$signature = $keys[0]->sign(
	Pkcs11\CKM_SHA256_RSA_PKCS_PSS,
	$data,
	new Pkcs11\RsaPssParams(Pkcs11\CKM_SHA256, Pkcs11\CKG_MGF1_SHA256, 32)
);

$session->logout();

$pem = rawToRsaPem($attributes[Pkcs11\CKA_MODULUS], $attributes[Pkcs11\CKA_PUBLIC_EXPONENT]);

$rsa = new RSA();
$rsa->setSignatureMode(RSA::SIGNATURE_PSS);
$rsa->loadKey($pem);
$rsa->setHash('sha256');
$rsa->setMGFHash('sha256');
$r = $rsa->verify($data, $signature);

echo "Data:\n" . bin2hex($data), PHP_EOL, PHP_EOL;
echo "Signature:\n" . bin2hex($signature), PHP_EOL, PHP_EOL;
echo "Public Exponent:\n" . bin2hex($attributes[Pkcs11\CKA_PUBLIC_EXPONENT]), PHP_EOL, PHP_EOL;
echo "Modulus:\n" . bin2hex($attributes[Pkcs11\CKA_MODULUS]), PHP_EOL, PHP_EOL;
echo 'Validates: ' . ($r ? 'Yes' : 'No'), PHP_EOL, PHP_EOL;


echo "B64 Signature:\n" . base64url_encode($signature), PHP_EOL, PHP_EOL;
echo $pem, PHP_EOL;
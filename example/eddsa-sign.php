<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module('/usr/local/lib/softhsm/libsofthsm2.so');
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER,'123456');

$domainParameters = hex2bin('06032B6570'); // Ed25519
$domainParameters = hex2bin('06032B6571'); // Ed448

$keypair = $session->generateKeyPair(Pkcs11\CKM_EC_EDWARDS_KEY_PAIR_GEN, [
	Pkcs11\CKA_VERIFY => true,
	Pkcs11\CKA_LABEL => "Test EDDSA Public",
	Pkcs11\CKA_EC_PARAMS => $domainParameters,
],[
	Pkcs11\CKA_TOKEN => true,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_LABEL => "Test EDDSA Private",
]);

$data = "Hello World!";
$signature = $keypair->skey->sign(Pkcs11\CKM_EDDSA, $data);
$check = $keypair->pkey->verify(Pkcs11\CKM_EDDSA, $data, $signature);

$session->logout();

echo "Data:\n" . bin2hex($data), PHP_EOL, PHP_EOL;
echo "Signature:\n" . bin2hex($signature), PHP_EOL, PHP_EOL;
echo 'Validates: ' . ($check ? 'Yes' : 'No'), PHP_EOL, PHP_EOL;

echo "B64 Signature:\n" . base64url_encode($signature), PHP_EOL, PHP_EOL;

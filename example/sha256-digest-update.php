<?php

declare(strict_types=1);

require 'helper.php';

use phpseclib\Crypt\RSA;

$module = new Pkcs11\Module($modulePath);
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER,'123456');

$key = $session->generateKey(new Pkcs11\Mechanism(Pkcs11\CKM_AES_KEY_GEN), [
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_SENSITIVE => false,
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_DECRYPT => true,
	Pkcs11\CKA_VALUE_LEN => 32,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_AES,
]);


function showAttributes(\Pkcs11\P11Object $object) {
	$attributes = $object->getAttributeValue([
		Pkcs11\CKA_VALUE,
	]);

	var_dump($attributes);
}

$digestContext = $session->initializeDigest(new Pkcs11\Mechanism(Pkcs11\CKM_SHA256));

$digestContext->update("Hello W");
$digestContext->update("orld!");
$digestContext->keyUpdate($key);
$digest = $digestContext->finalize();
var_dump($digest);

$session->logout();

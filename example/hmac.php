<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module($modulePath);
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER,'123456');

$key = $session->generateKey(new Pkcs11\Mechanism(Pkcs11\CKM_GENERIC_SECRET_KEY_GEN), [
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_VALUE_LEN => 32,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_GENERIC_SECRET,
	Pkcs11\CKA_LABEL => "Test HMAC",
]);

$data = "Hello World!";
$mac = $key->sign(new Pkcs11\Mechanism(Pkcs11\CKM_SHA256_HMAC), $data);
var_dump($mac);

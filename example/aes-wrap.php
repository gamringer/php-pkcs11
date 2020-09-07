<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module($modulePath);
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, $pinCode);

$wkey = $session->generateKey(new Pkcs11\Mechanism(Pkcs11\CKM_AES_KEY_GEN), [
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_DECRYPT => true,
	Pkcs11\CKA_WRAP => true,
	Pkcs11\CKA_UNWRAP => true,
	Pkcs11\CKA_VALUE_LEN => 32,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_AES,
	Pkcs11\CKA_LABEL => "Test Wrapping AES",
	Pkcs11\CKA_PRIVATE => true,
]);

$key = $session->generateKey(new Pkcs11\Mechanism(Pkcs11\CKM_AES_KEY_GEN), [
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_DECRYPT => true,
	Pkcs11\CKA_VALUE_LEN => 32,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_AES,
	Pkcs11\CKA_LABEL => "Test AES",
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_EXTRACTABLE => true,
]);

$ciphertext = $wkey->wrap(new Pkcs11\Mechanism(Pkcs11\CKM_AES_KEY_WRAP), $key);
var_dump(bin2hex($ciphertext));

$uwkey = $key->unwrap(new Pkcs11\Mechanism(Pkcs11\CKM_AES_KEY_WRAP), $ciphertext, [
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_DECRYPT => true,
	Pkcs11\CKA_VALUE_LEN => 32,
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_DECRYPT => true,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_AES,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_EXTRACTABLE => true,
]);
/*
var_dump($plaintext);

showAttributes($key);


function showAttributes(\Pkcs11\P11Object $object) {
	$attributes = $object->getAttributeValue([
		Pkcs11\CKA_LABEL,
	]);

	var_dump($attributes);
}
*/
$session->logout();

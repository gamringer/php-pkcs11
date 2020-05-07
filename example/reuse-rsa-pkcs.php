<?php

declare(strict_types=1);

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

var_dump($attributes[Pkcs11\CKA_PUBLIC_EXPONENT]);
var_dump($attributes[Pkcs11\CKA_MODULUS]);

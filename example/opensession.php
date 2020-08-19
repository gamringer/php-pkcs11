<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module($modulePath);


$slotList = $module->getSlotList();

var_dump($slotList);
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
var_dump($module);
var_dump($session);
var_dump($session->getInfo()['state']);
$session->login(Pkcs11\CKU_SO,'12345678');
var_dump($session->getInfo()['state']);
$session->logout();
var_dump($session->getInfo()['state']);
$session->login(Pkcs11\CKU_USER,'123456');
var_dump($session->getInfo()['state']);
$session->logout();
var_dump($session->getInfo()['state']);

$info = $module->C_GetSessionInfo($session);
var_dump($info);

var_dump($session->getInfo()['state']);
$module->C_Login($session, Pkcs11\CKU_USER, '123456');
var_dump($session->getInfo()['state']);
$module->C_Logout($session);
var_dump($session->getInfo()['state']);

$module->C_Login($session, Pkcs11\CKU_USER, '123456');

$keypair = $module->C_GenerateKeyPair($session, new Pkcs11\Mechanism(Pkcs11\CKM_RSA_PKCS_KEY_PAIR_GEN), [
	Pkcs11\CKA_VERIFY => true,
	Pkcs11\CKA_MODULUS_BITS => 2048,
	Pkcs11\CKA_PUBLIC_EXPONENT => hex2bin('010001'),
	Pkcs11\CKA_LABEL => "Test RSA Public",
],[
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_SIGN => true,
	Pkcs11\CKA_LABEL => "Test RSA Private",
]);

var_dump($keypair);
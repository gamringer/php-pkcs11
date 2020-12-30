<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module($modulePath);

$rv = $module->C_GetInfo($info);
var_dump('RV: ' . dechex($rv));
var_dump($info);

$rv = $module->C_GetSlotList(true, $slotList);
var_dump('RV: ' . dechex($rv));
var_dump($slotList);

$rv = $module->C_GetSlotInfo($slotList[0], $slotInfo);
var_dump('RV: ' . dechex($rv));
var_dump($slotInfo);

$rv = $module->C_GetTokenInfo($slotList[0], $tokenInfo);
var_dump('RV: ' . dechex($rv));
var_dump($tokenInfo);

$rv = $module->C_GetMechanismList($slotList[0], $mechanismList);
var_dump('RV: ' . dechex($rv));
var_dump($mechanismList);

$rv = $module->C_GetMechanismInfo($slotList[0], Pkcs11\CKM_AES_GCM, $mechanismInfo);
var_dump('RV: ' . dechex($rv));
var_dump($mechanismInfo);

$rv = $module->C_InitToken(0, 'PHP slot', '123456');
var_dump('RV: ' . dechex($rv));

$rv = $module->C_OpenSession($slotList[0], Pkcs11\CKF_SERIAL_SESSION | Pkcs11\CKF_RW_SESSION, null, null, $session);
var_dump('RV: ' . dechex($rv));
var_dump($session);

$rv = $module->C_GetSessionInfo($session, $info);
var_dump('RV: ' . dechex($rv));
var_dump($info);

$rv = $module->C_Login($session, Pkcs11\CKU_SO, $sopinCode);
var_dump('RV: ' . dechex($rv));

$rv = $module->C_InitPIN($session, $pinCodeReplaced);
var_dump('RV: ' . dechex($rv));

$rv = $module->C_Logout($session);
var_dump('RV: ' . dechex($rv));

$rv = $module->C_Login($session, Pkcs11\CKU_USER, $pinCode);
var_dump('RV: ' . dechex($rv));

$rv = $module->C_Login($session, Pkcs11\CKU_SO, $sopinCode);
var_dump('RV: ' . dechex($rv));

$rv = $module->C_InitPIN($session, $pinCode);
var_dump('RV: ' . dechex($rv));

$rv = $module->C_Logout($session);
var_dump('RV: ' . dechex($rv));

$rv = $module->C_SetPIN($session, $pinCode, $pinCodeReplaced);
var_dump('RV: ' . dechex($rv));

$rv = $module->C_Logout($session);
var_dump('RV: ' . dechex($rv));

$rv = $module->C_Login($session, Pkcs11\CKU_USER, $pinCode);
var_dump('RV: ' . dechex($rv));

$rv = $module->C_Login($session, Pkcs11\CKU_USER, $pinCodeReplaced);
var_dump('RV: ' . dechex($rv));

$rv = $module->C_SetPIN($session, $pinCodeReplaced, $pinCode);
var_dump('RV: ' . dechex($rv));

$rv = $module->C_Logout($session);
var_dump('RV: ' . dechex($rv));

$rv = $module->C_Login($session, Pkcs11\CKU_USER, $pinCode);
var_dump('RV: ' . dechex($rv));



$rv = $module->C_GenerateKey($session, new Pkcs11\Mechanism(Pkcs11\CKM_AES_KEY_GEN), [
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_DECRYPT => true,
	Pkcs11\CKA_VALUE_LEN => 32,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_AES,
	Pkcs11\CKA_LABEL => "Test AES",
	Pkcs11\CKA_PRIVATE => true,
], $key);
var_dump('RV: ' . dechex($rv));
var_dump($key);

/*
$module->C_DigestInit($session, new Pkcs11\Mechanism(Pkcs11\CKM_SHA256));
$digest = $module->C_Digest($session, "allo");
var_dump($digest);

$module->C_DigestInit($session, new Pkcs11\Mechanism(Pkcs11\CKM_SHA256));
$module->C_DigestUpdate($session, "al");
$module->C_DigestUpdate($session, "lo");
$digest = $module->C_DigestFinal($session);
var_dump($digest);

$module->C_DigestInit($session, new Pkcs11\Mechanism(Pkcs11\CKM_SHA256));
$module->C_DigestUpdate($session, "al");
$module->C_DigestKey($session, $key);
$module->C_DigestUpdate($session, "lo");
$digest = $module->C_DigestFinal($session);
var_dump($digest);

$object = $module->C_CreateObject($session, [
	Pkcs11\CKA_CLASS => Pkcs11\CKO_DATA,
	Pkcs11\CKA_APPLICATION => "Some App",
	Pkcs11\CKA_VALUE => 'Hello World!',
	Pkcs11\CKA_LABEL => "Original Label",
]);
var_dump($object);
$attributes = $object->getAttributeValue([
	Pkcs11\CKA_VALUE,
	Pkcs11\CKA_APPLICATION,
]);
var_dump($attributes);


$found = $module->C_FindObjects($session, [
	Pkcs11\CKA_LABEL => "Original Label",
]);
var_dump($found);
$attributes = $found[0]->getAttributeValue([
	Pkcs11\CKA_VALUE,
	Pkcs11\CKA_APPLICATION,
]);
var_dump($attributes);

$copy = $module->C_CopyObject($session, $object, [
	Pkcs11\CKA_LABEL => "New Label",
]);
var_dump($copy);
$attributes = $copy->getAttributeValue([
	Pkcs11\CKA_LABEL,
	Pkcs11\CKA_VALUE,
	Pkcs11\CKA_APPLICATION,
]);
var_dump($attributes);


$module->C_DestroyObject($session, $object);
$module->C_DestroyObject($session, $copy);

$found = $module->C_FindObjects($session, [
	Pkcs11\CKA_LABEL => "Original Label",
]);
var_dump($found);

*/
$rv = $module->C_GenerateKeyPair(
	$session,
	new Pkcs11\Mechanism(Pkcs11\CKM_RSA_PKCS_KEY_PAIR_GEN),
	[
		Pkcs11\CKA_ENCRYPT => true,
		Pkcs11\CKA_MODULUS_BITS => 2048,
		Pkcs11\CKA_PUBLIC_EXPONENT => hex2bin('010001'),
		Pkcs11\CKA_LABEL => "Test RSA Encrypt Public",
	],
	[
		Pkcs11\CKA_TOKEN => false,
		Pkcs11\CKA_PRIVATE => true,
		Pkcs11\CKA_SENSITIVE => true,
		Pkcs11\CKA_DECRYPT => true,
		Pkcs11\CKA_LABEL => "Test RSA Encrypt Private",
	]
	,$pkey,$skey
);
var_dump('RV: ' . dechex($rv));
var_dump($pkey, $skey);

<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module($modulePath);
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER,'123456');

$object = $session->createObject([
	Pkcs11\CKA_CLASS => Pkcs11\CKO_DATA,
	Pkcs11\CKA_APPLICATION => "Some App",
	Pkcs11\CKA_VALUE => 'Hello World!',
]);
var_dump($object);

$attributes = $object->getAttributeValue([
	Pkcs11\CKA_VALUE,
	Pkcs11\CKA_TOKEN,
]);

var_dump($attributes);

$copy = $session->copyObject($object, [
	Pkcs11\CKA_TOKEN => true,
]);

var_dump($copy);

$attributes = $copy->getAttributeValue([
	Pkcs11\CKA_VALUE,
	Pkcs11\CKA_TOKEN,
]);

var_dump($attributes);


$session->destroyObject($copy);


$attributes = $copy->getAttributeValue([
	Pkcs11\CKA_VALUE,
	Pkcs11\CKA_TOKEN,
]);

var_dump($attributes);

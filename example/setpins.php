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
$session->initPin('654321');
$session->logout();
var_dump($session->getInfo()['state']);
$session->login(Pkcs11\CKU_USER,'654321');
var_dump($session->getInfo()['state']);
$session->logout();
var_dump($session->getInfo()['state']);
$session->login(Pkcs11\CKU_SO,'12345678');
var_dump($session->getInfo()['state']);
$session->initPin('123456');
$session->logout();
var_dump($session->getInfo()['state']);
$session->login(Pkcs11\CKU_USER,'123456');
var_dump($session->getInfo()['state']);
$session->setPin('123456', 'abcdef');
$session->logout();
var_dump($session->getInfo()['state']);
$session->login(Pkcs11\CKU_USER,'abcdef');
var_dump($session->getInfo()['state']);
$session->setPin('abcdef', '123456');
$session->logout();
var_dump($session->getInfo()['state']);
$session->login(Pkcs11\CKU_USER,'123456');
var_dump($session->getInfo()['state']);
$session->logout();

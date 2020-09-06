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
$session->login(Pkcs11\CKU_USER,$pinCode);
var_dump($session->getInfo()['state']);
$session->logout();
var_dump($session->getInfo()['state']);

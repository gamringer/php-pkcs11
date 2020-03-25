<?php

declare(strict_types=1);

$module = new Pkcs11\Module('/usr/lib/softhsm/libsofthsm2.so');


$slotList = $module->getSlotList();

var_dump($slotList);
$session = $module->openSession($slotList[0], PKCS11\CKF_RW_SESSION);
echo 'lala';
var_dump($module);
var_dump($session);
$session->login(1,'123456');
echo 'lolo';

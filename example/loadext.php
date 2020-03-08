<?php

declare(strict_types=1);

$module = new Pkcs11\Module('/usr/lib/softhsm/libsofthsm2.so');


$slotList = $module->getSlotList();
var_dump($slotList);

$mechanismList = $module->getMechanismList($slotList[0]);
var_dump($mechanismList);

$mechanismInfo = $module->getMechanismInfo($slotList[0], $mechanismList[48]);
var_dump($mechanismInfo);
var_dump(PKCS11\CKM_SHA1_RSA_PKCS);

/*
$info = $module->getInfo();
var_dump($info);

$slots = $module->getSlots();
var_dump($slots);

$slotList = $module->getSlotList();
var_dump($slotList);

$slotInfo = $module->getSlotInfo($slotList[0]);
var_dump($slotInfo);

$tokenInfo = $module->getTokenInfo($slotList[0]);
var_dump($tokenInfo);

/*
$module->initToken(5, 'PHP slot', '123456');

$slots = $module->getSlots();
var_dump($slots);
*/
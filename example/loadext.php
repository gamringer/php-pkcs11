<?php

declare(strict_types=1);

$module = new Pkcs11\Module('/usr/lib/softhsm/libsofthsm2.so');

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
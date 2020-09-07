<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module($modulePath);


$slotList = $module->getSlotList();
var_dump($slotList);

$mechanismList = $module->getMechanismList($slotList[0]);
print_r($mechanismList);
foreach ($mechanismList as $i => $mechanismId) {
	if ($mechanismId == Pkcs11\CKM_AES_GCM) {
		$mechanismInfo = $module->getMechanismInfo($slotList[0], $mechanismList[$i]);
		var_dump($mechanismInfo);
	}
}

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
$module->initToken(5, 'PHP slot', $pinCode);

$slots = $module->getSlots();
var_dump($slots);
*/

<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module($modulePath);


$slotList = $module->C_GetSlotList();
var_dump($slotList);

$mechanismList = $module->C_GetMechanismList($slotList[0]);
print_r($mechanismList);
foreach ($mechanismList as $i => $mechanismId) {
	if ($mechanismId == Pkcs11\CKM_AES_GCM) {
		$mechanismInfo = $module->C_GetMechanismInfo($slotList[0], $mechanismList[$i]);
		var_dump($mechanismInfo);
	}
}

/*
$info = $module->C_GetInfo();
var_dump($info);

$slots = $module->C_GetSlots();
var_dump($slots);

$slotList = $module->C_GetSlotList();
var_dump($slotList);

$slotInfo = $module->C_GetSlotInfo($slotList[0]);
var_dump($slotInfo);

$tokenInfo = $module->C_GetTokenInfo($slotList[0]);
var_dump($tokenInfo);

/*
$module->C_InitToken(5, 'PHP slot', $pinCode);

$slots = $module->C_GetSlots();
var_dump($slots);
*/

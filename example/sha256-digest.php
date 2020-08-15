<?php

declare(strict_types=1);

require 'helper.php';

use phpseclib\Crypt\RSA;

$module = new Pkcs11\Module($modulePath);
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER,'123456');

$data = "Hello World!";
$digest = $session->digest(Pkcs11\CKM_SHA256, $data);
var_dump($digest);

$digest2 = hash('sha256', $data, true);
var_dump($digest2);

var_dump($digest == $digest2);

$session->logout();

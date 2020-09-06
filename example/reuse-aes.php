<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module($modulePath);
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, $pinCode);

$keys = $session->findObjects([
	Pkcs11\CKA_LABEL => "Test AES",
]);

var_dump($keys[0]);

$iv = random_bytes(16);
$data = 'Hello World!';
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_AES_CBC_PAD, $iv);
$ciphertext = $keys[0]->encrypt($mechanism, $data);
var_dump(bin2hex($ciphertext));

$plaintext = $keys[0]->decrypt($mechanism, $ciphertext);
var_dump($plaintext);

<?php

declare(strict_types=1);

require 'helper.php';

$module = new Pkcs11\Module($modulePath);
$slotList = $module->getSlotList();
$session = $module->openSession($slotList[0], Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, $pinCode);
/*
$key = $session->generateKey(new Pkcs11\Mechanism(Pkcs11\CKM_CHACHA20_KEY_GEN), [
	Pkcs11\CKA_CLASS => Pkcs11\CKO_SECRET_KEY,
	Pkcs11\CKA_TOKEN => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_KEY_TYPE => Pkcs11\CKK_CHACHA20,
	Pkcs11\CKA_LABEL => "Test AES",
	Pkcs11\CKA_PRIVATE => true,
]);

$iv = random_bytes(16);
$data = 'Hello World!';
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_CHACHA20_POLY1305, $iv);
$ciphertext = $key->encrypt($mechanism, $data);
var_dump(bin2hex($ciphertext));

$plaintext = $key->decrypt($mechanism, $ciphertext);
var_dump($plaintext);
*/

$aad = '';
$c20Params = new Pkcs11\ChaCha20Params(random_bytes(24));
$s20Params = new Pkcs11\Salsa20Params(random_bytes(24));
$cs20pParams = new Pkcs11\Salsa20Chacha20Poly1305Params(random_bytes(24), $aad);

$session->logout();

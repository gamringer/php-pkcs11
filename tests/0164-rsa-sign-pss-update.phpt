--TEST--
Sign/Verify using RSA PSS with update
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

if (!in_array(Pkcs11\CKM_SHA256_RSA_PKCS_PSS, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
	echo 'skip: CKM_SHA256_RSA_PKCS_PSS not supported ';
}

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$keypair = $session->generateKeyPair(new Pkcs11\Mechanism(Pkcs11\CKM_RSA_PKCS_KEY_PAIR_GEN), [
	Pkcs11\CKA_VERIFY => true,
	Pkcs11\CKA_MODULUS_BITS => 2048,
	Pkcs11\CKA_PUBLIC_EXPONENT => hex2bin('010001'),
	Pkcs11\CKA_LABEL => "Test RSA Public",
],[
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_SIGN => true,
	Pkcs11\CKA_LABEL => "Test RSA Private",
]);

$pssParams = new Pkcs11\RsaPssParams(Pkcs11\CKM_SHA256, Pkcs11\CKG_MGF1_SHA256, 32);
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_SHA256_RSA_PKCS_PSS, $pssParams);

$signatureContext = $keypair->skey->initializeSignature($mechanism);

$signatureContext->update('Hello Wo');
$signatureContext->update('rld!');
$signature = $signatureContext->finalize();

var_dump(bin2hex($signature));

$verificationContext = $keypair->pkey->initializeVerification($mechanism);

$verificationContext->update('Hello Wo');
$verificationContext->update('rld!');
$verifies = $verificationContext->finalize($signature);

var_dump($verifies);

$session->logout();

?>
--EXPECTF--
string(512) "%x"
bool(true)

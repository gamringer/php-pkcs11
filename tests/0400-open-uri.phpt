--TEST--
Find object and retrieve attributes
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

require_once 'require-create-object.skipif.inc';

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$session->generateKeyPair(new Pkcs11\Mechanism(Pkcs11\CKM_RSA_PKCS_KEY_PAIR_GEN), [
	Pkcs11\CKA_ENCRYPT => true,
	Pkcs11\CKA_MODULUS_BITS => 2048,
	Pkcs11\CKA_PUBLIC_EXPONENT => hex2bin('010001'),
	Pkcs11\CKA_LABEL => "testPkcs11Url",
],[
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_DECRYPT => true,
	Pkcs11\CKA_LABEL => "testPkcs11Url",
]);

$key = $session->openUrl("pkcs11:object=testPkcs11Url;type=private;");

$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_SHA256_RSA_PKCS);

$data = "Hello World!";
$signature = $key[0]->sign($mechanism, $data);
var_dump(bin2hex($signature));

$key = $session->openUrl("pkcs11:object=testPkcs11Url;type=public");
$valid = $key[0]->verify($mechanism, $data, $signature);
var_dump($valid);

$session->logout();


?>
--EXPECTF--
string(512) "%x"
bool(true)

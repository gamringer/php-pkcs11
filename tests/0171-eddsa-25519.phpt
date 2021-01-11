--TEST--
Sign/Verify using EdDSA 25519
--SKIPIF--
<?php

require_once 'require-userpin-login.skipif.inc';

if (!in_array(Pkcs11\CKM_EDDSA, $module->getMechanismList((int)getenv('PHP11_SLOT')))) {
	echo 'skip: CKM_EDDSA not supported ';
}

require_once 'require-generate-key-pair.skipif.inc';

?>
--FILE--
<?php

declare(strict_types=1);

$module = new Pkcs11\Module(getenv('PHP11_MODULE'));
$session = $module->openSession((int)getenv('PHP11_SLOT'), Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, getenv('PHP11_PIN'));

$domainParameters = hex2bin('06032B6570');

$keypair = $session->generateKeyPair(new Pkcs11\Mechanism(Pkcs11\CKM_EC_EDWARDS_KEY_PAIR_GEN), [
	Pkcs11\CKA_VERIFY => true,
	Pkcs11\CKA_LABEL => "Test EDDSA Public",
	Pkcs11\CKA_EC_PARAMS => $domainParameters,
],[
	Pkcs11\CKA_TOKEN => false,
	Pkcs11\CKA_PRIVATE => true,
	Pkcs11\CKA_SENSITIVE => true,
	Pkcs11\CKA_LABEL => "Test EDDSA Private",
]);

$data = "Hello World!";
$mechanism = new Pkcs11\Mechanism(Pkcs11\CKM_EDDSA);
$signature = $keypair->skey->sign($mechanism, $data);
$check = $keypair->pkey->verify($mechanism, $data, $signature);

$session->logout();

var_dump(bin2hex($data));
var_dump(bin2hex($signature));
var_dump(bin2hex(substr($signature,  0, 32)));
var_dump(bin2hex(substr($signature, 32, 32)));
echo 'Validates: ' . ($check ? 'Yes' : 'No'), PHP_EOL;

?>
--EXPECTF--
string(24) "48656c6c6f20576f726c6421"
string(128) "%x"
string(64) "%x"
string(64) "%x"
Validates: Yes
